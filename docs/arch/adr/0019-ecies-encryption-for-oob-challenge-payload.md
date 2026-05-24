---
status: accepted
date: 2026-05-23
deciders: [farchanjo]
consulted: [Architecture, Security]
informed: [Engineering]
---

# 0019. ECIES Encryption for OOB Challenge Payload

## Context and Problem Statement

The [Handle default exposure model](0007-handle-default-exposure-model.md)
establishes that a Handle URI (`vault://<namespace>/<category>/<name>`)
carries operational intelligence: from its structure alone an observer can
infer the namespace, category, and name of any secret the Vault Agent holds.
The model prohibits plaintext credentials from crossing the MCP transport, but
it does not govern what subscribers on the Companion Socket may observe about
pending Reveal operations.

The OOB Confirmation flow established in
[ADR-0011 and its Amendment](0011-slash-only-reveal-with-oob-for-high-sensitivity.md)
dispatches an `OobChallenge` event over the Companion Socket when a
`sensitivity=high` Reveal is initiated. Post-W2.B, the `OobChallenge` payload
fields are: `challenge_id`, `secret_handle` (full URI
`vault://<ns>/<cat>/<name>`), `sensitivity`, `expires_at`, `oob_channel`,
`namespace_id`, and `request_nonce`. The `approval_url` field was removed in
the W2.B Amendment for security reasons, but the handle URI itself was
retained.

The Companion Socket is authenticated: peer credentials are verified at
`accept(2)` time via platform-specific mechanisms (Linux `SCM_CREDENTIALS`,
macOS `LOCAL_PEERCRED`, Windows `GetNamedPipeClientProcessId`) as described in
[ADR-0015](0015-rust-keyring-crate-for-multi-os-keychain.md). Any local
process whose binary path matches the `allowed_consumers` glob list in the
Namespace Policy may subscribe and receive events on the socket.

The W4.B STRIDE threat expansion identified the following residual risk: a
compromised allowlisted process subscribing to `oob/challenge/issued` receives
the `secret_handle` field in plaintext on every high-sensitivity Reveal
attempt. Over time, the subscriber accumulates a complete map of
high-sensitivity secrets — their namespaces, categories, and names — without
ever triggering a Reveal and without appearing in the audit log. A
prompt-injection adversary can further correlate handle names with audit log
entries to reconstruct the full credential landscape.

The threat is distinct from unauthorized access (which peer-credential
authentication addresses): it targets authorized subscribers who should route
events but should not read the secret identity embedded in the payload.

This ADR decides whether, and how, to encrypt the `OobChallenge` payload such
that only the enrolled Companion Device can decrypt it, while preserving
transport-routing metadata in an unencrypted envelope visible to all
subscribers.

## Decision Drivers

* **Handle URI confidentiality**: the `secret_handle` field is the primary
  information-leakage vector. An enumeration attack requires no Reveal and
  leaves no audit footprint.
* **Authorized-but-not-entitled subscriber model**: Companion Socket peer-auth
  determines which processes may connect, not which fields they may read.
  Defense-in-depth requires a second layer below process identity.
* **Enrolled device binding**: the ADR-0011 Amendment's enrollment ceremony
  already establishes a long-term Ed25519 keypair per Companion Device. Any
  encryption scheme must reuse or extend that material without adding a
  separate enrollment step.
* **AEAD primitive consistency**: [ADR-0004](0004-xchacha20-poly1305-aead-for-blobs.md)
  mandates XChaCha20-Poly1305 with 24-byte nonces for blob encryption. The OOB
  encryption choice must be consistent with or justified against that baseline.
* **Operator UX**: the Companion Device must present the human-readable secret
  name to the operator at approval time. Encryption must not suppress the
  handle from the enrolled device; it must suppress it from all other
  subscribers.
* **Audit accountability**: post-hoc verification that the Vault Agent
  encrypted to the correct device must be possible from the audit log alone,
  without decrypting the ciphertext.
* **Backward compatibility**: legacy companion devices enrolled before this ADR
  (which hold only an Ed25519 key, not an X25519 key) must not be hard-blocked;
  a graduated fallback path is required during the transition window.

## Considered Options

* Option A: Status quo — no payload encryption; rely on peer-credential
  authentication at the Companion Socket
* Option B: Full-payload ECIES (X25519 + XChaCha20-Poly1305) to enrolled
  Companion Device public key
* Option C: Field-level encryption of `secret_handle` only
* Option D: Signed-opaque-digest — replace `secret_handle` with
  `BLAKE3(handle || request_nonce)`

## Decision Outcome

Chosen option: **Option B — Full-payload ECIES to enrolled Companion Device**,
because it is the only option that completely eliminates the handle-URI
information-leakage vector at the socket layer without degrading operator UX.
Options A and C both leave the handle visible to socket subscribers (fully or
partially). Option D eliminates the leak but breaks the operator confirmation
UX by suppressing the human-readable secret name from the Companion Device
display.

### Key Material Binding

The ADR-0011 Amendment enrollment ceremony generates one Ed25519 signing
keypair per Companion Device. This ADR extends that ceremony to generate a
second keypair: an X25519 key used exclusively for ECIES encryption.

The extension is implemented by one of two mechanisms, ranked by preference:

1. **Preferred — Direct X25519 keypair generation**: during `merkle device
   pair`, `OsRng` generates a separate 32-byte X25519 scalar as the private
   key. The corresponding X25519 public key (Curve25519 basepoint
   multiplication) is stored in the vault's sealed state alongside the Ed25519
   public key, keyed by `device-id`. The X25519 private key is stored in the
   same OS keychain entry `merkle-companion-<device-id>` as the Ed25519 private
   key, distinguished by a sub-key field name (e.g., `x25519_private` vs.
   `ed25519_private`).

2. **Fallback — Birational map from Ed25519 scalar**: RFC 7748 §4.3 defines
   the birational equivalence between Edwards25519 and Montgomery Curve25519.
   An Ed25519 private key (the expanded seed's first 32 bytes, after clamping)
   can be converted to an X25519 scalar via the standard conversion formula.
   This fallback avoids a second keychain entry but derives encryption key
   material from signing key material, which violates key separation principles.
   The fallback is permitted only for Companion Device implementations where
   adding a second keychain entry is not operationally feasible, and MUST be
   documented in the device's enrollment record.

The Vault Agent retrieves the X25519 public key from the sealed state for the
enrolled device identified in the Reveal request.

### ECIES Construction

For each `OobChallenge`, the Vault Agent:

1. Generates an ephemeral X25519 keypair using `OsRng`.
2. Performs X25519 Diffie-Hellman between the ephemeral private key and the
   enrolled device's long-term X25519 public key, producing a 32-byte shared
   secret.
3. Derives a 32-byte encryption key via BLAKE3 key derivation function with
   context string `"merkle oob-challenge v1 encryption"` and the shared secret
   as key material.
4. Generates a 24-byte nonce from `OsRng` (XChaCha20-Poly1305 nonce, aligned
   with ADR-0004's 24-byte nonce discipline).
5. Serializes the full `OobChallenge` inner payload (all fields including
   `secret_handle`) to canonical JSON.
6. Encrypts with XChaCha20-Poly1305: `Encrypt(key, nonce, plaintext,
   aad=challenge_id)`. The `challenge_id` is bound as AEAD associated data,
   preventing ciphertext transplantation between challenges.
7. Publishes the event with a split envelope:

   - **Routing envelope (plaintext)**: `event_type`, `event_version`,
     `vault_id`, `timestamp`, `challenge_id`, `oob_channel`, `expires_at`.
     These fields are sufficient for transport routing and timeout tracking.
   - **Encrypted body**: `{ephemeral_pubkey: <base64url>, nonce: <base64url>,
     ciphertext: <base64url>, tag: <base64url>}`. Subscribers other than the
     enrolled Companion Device receive opaque bytes.

### Nonce Policy

Each challenge uses a fresh 24-byte nonce drawn from `OsRng`. The nonce
discipline mirrors ADR-0004: 24-byte nonces at XChaCha20-Poly1305 volume
make random-nonce collision probability negligible. The entropy gate mandated
in the ADR-0004 Amendment (Linux `/proc/sys/kernel/random/entropy_avail`
threshold, CRNG initialization barrier) applies equally to ECIES nonce
generation.

### Failure Mode

If the Companion Device cannot decrypt the payload (ciphertext corruption,
wrong key, in-flight key rotation), the device MUST return a `denied` response
with `denial_reason=oob_decrypt_failure`. The Vault Agent treats this response
identically to an operator-initiated denial: the Reveal is rejected, an
`oob_decrypt_failure` audit entry is emitted, and `confirmation_required` is
returned to the caller. There is no plaintext fallback path.

### Backward Compatibility

Companion devices enrolled before this ADR hold only an Ed25519 key; no
X25519 public key is stored in the vault sealed state for such devices. The
Vault Agent detects the absence of an X25519 public key in the sealed state
and falls back to Option C behavior: the `secret_handle` field is encrypted
using a separate field-level key derivation path (defined in the follow-up
implementation dispatch), while the remaining fields remain plaintext. The
fallback is logged as a `oob_encryption_degraded` audit entry. Operators are
expected to re-enroll devices within one release cycle of this ADR's
implementation.

### Audit Accountability

The audit entry for an encrypted challenge includes:
- `ephemeral_pubkey`: the base64url-encoded ephemeral X25519 public key used
  for ECIES.
- `ciphertext_digest`: BLAKE3 of the ciphertext bytes.
- `enrolled_device_id`: the `device-id` identifying which long-term X25519
  public key was targeted.

A security auditor can verify post-hoc that the Vault Agent encrypted to the
correct enrolled device by re-running the X25519 scalar multiplication with
the enrolled device's known public key and confirming the ephemeral public key
participates in the same elliptic curve group.

### Consequences

* Good, because the `secret_handle` URI is no longer visible to any Companion
  Socket subscriber except the enrolled Companion Device, eliminating the
  passive enumeration attack entirely.
* Good, because the ECIES construction reuses the XChaCha20-Poly1305 primitive
  already mandated by ADR-0004, keeping the cryptographic dependency surface
  minimal.
* Good, because binding `challenge_id` as AEAD associated data prevents
  ciphertext replay across challenges.
* Good, because the routing envelope preserves the fields needed for timeout
  enforcement and transport routing without decryption.
* Good, because the audit record of `ephemeral_pubkey` + `ciphertext_digest`
  provides post-hoc accountability without requiring the auditor to hold a
  decryption key.
* Bad, because the enrollment ceremony gains a step (X25519 keypair
  generation), adding implementation surface and requiring re-enrollment for
  existing companion devices.
* Bad, because legacy companion devices fall back to field-level encryption
  (Option C behavior) rather than full-payload encryption, creating a
  transitional period where partial protection is in effect.
* Neutral, because ECIES with an ephemeral keypair per challenge adds one
  scalar multiplication and one XChaCha20-Poly1305 operation per Reveal; this
  is negligible latency at the expected Reveal volume.

## Pros and Cons of the Options

### Option A: Status Quo (No Payload Encryption)

* Good, because no implementation changes are required; the existing
  peer-credential mechanism at the Companion Socket provides process-level
  access control.
* Good, because the plaintext payload simplifies debugging and operational
  inspection of OOB challenge flows.
* Bad, because any allowlisted process — whether legitimately authorized or
  compromised — can read the `secret_handle` URI in plaintext and accumulate
  an enumeration of all high-sensitivity secrets over time.
* Bad, because the passive enumeration attack leaves no audit footprint; the
  Vault Agent has no mechanism to detect or prevent it at the socket layer.
* Bad, because peer-credential authentication addresses the question of which
  processes may connect, not which payload fields they may read; the threat
  model requires a second defense layer independent of process identity.

### Option B: Full-Payload ECIES to Enrolled Companion Device (Chosen)

* Good, because the full inner payload — including `secret_handle`,
  `sensitivity`, `namespace_id`, and `request_nonce` — is opaque to all
  subscribers except the enrolled device, eliminating the enumeration threat
  at every field simultaneously.
* Good, because the X25519 + XChaCha20-Poly1305 ECIES construction aligns
  with the ADR-0004 AEAD baseline and the ADR-0011 Amendment Ed25519
  enrollment ceremony, reusing existing key material infrastructure.
* Good, because the plaintext routing envelope preserves transport-routing
  semantics without requiring decryption by intermediary processes.
* Bad, because the X25519 keypair must be added to the enrollment ceremony
  and stored in the vault sealed state, expanding the key management surface.
* Bad, because companion devices enrolled before this ADR require a
  re-enrollment step; a backward-compatible fallback (Option C behavior)
  is required during the transition period.

### Option C: Field-Level Encryption (Handle Only)

* Good, because it targets the highest-value information-leakage field
  (`secret_handle`) while leaving the remaining fields plaintext, simplifying
  debugging by keeping `sensitivity`, `expires_at`, and `oob_channel` visible.
* Good, because implementation scope is smaller than Option B: only one field
  is encrypted.
* Bad, because `sensitivity=high` and `namespace_id` remain visible to all
  subscribers; an attacker learns which namespace is accessed at high
  sensitivity, narrowing the enumeration space even without the handle name.
* Bad, because partial protection creates a false confidence boundary: the
  payload is described as "encrypted" but delivers two thirds of the
  operational intelligence to any subscriber.
* Neutral, because this option is designated the backward-compatibility
  fallback for legacy companion devices under Option B; it is not an
  independent primary choice.

### Option D: Signed-Opaque-Digest (No Decryption)

* Good, because replacing `secret_handle` with `BLAKE3(handle || request_nonce)`
  provides maximum confidentiality: even the enrolled Companion Device cannot
  reconstruct the handle name from the digest alone.
* Good, because no decryption key management is required on the Companion
  Device; the device signs the digest and returns the signature.
* Bad, because the operator cannot see which secret they are approving; the
  Companion Device UX displays only an opaque hash. This breaks the
  operator confirmation UX requirement: an operator approving a high-sensitivity
  Reveal must be able to read the secret name to make an informed decision.
* Bad, because a prompt-injection adversary who can trigger a Reveal can trick
  an operator into approving it without the operator understanding which secret
  is being revealed, degrading the security guarantee that OOB Confirmation
  provides.
* Neutral, because the digest approach would be appropriate in fully automated
  pipeline contexts where no human reads the Companion Device display, but
  Merkle's OOB model is explicitly operator-facing.

## Validation

- Gherkin feature `reveal_with_oob.feature` MUST add two new scenarios:
  - `"OobChallenge decrypts only on enrolled device"` — assert that a subscriber
    with the correct X25519 private key decrypts successfully and that a
    subscriber with a different key receives an AEAD authentication error.
  - `"OobChallenge denied when decryption fails"` — assert that the Vault Agent
    treats a `denial_reason=oob_decrypt_failure` response as a `denied` outcome
    and emits the correct audit entry.
- AsyncAPI spec `docs/arch/integrations/asyncapi/audit-and-oob.yaml` MUST be
  updated to add the encrypted envelope schema on the `OobChallengeIssued`
  message: `{ephemeral_pubkey: string, nonce: string, ciphertext: string,
  tag: string}` with the plaintext routing envelope fields documented
  separately.
- CUE schema `docs/arch/schemas/access_mediation/oob_resolution.cue` MUST be
  extended with an `#OobChallengeEncryptedEnvelope` definition capturing the
  ECIES envelope fields and their base64url format constraints.
- TLA+ module `docs/arch/formal/AEADNonceDiscipline.tla` MAY be extended with
  a parallel ECIES nonce-discipline check verifying that per-challenge nonces
  are never reused across concurrent or sequential Reveal operations.
- `spec validate --lane full` exits 0 with `lint_madr 19/19 passed` and all
  14 validators green. The new scenarios and schema changes must not introduce
  regressions in existing validators.

## More Information

This ADR records the encryption policy decision only. The following follow-up
implementation artifacts are required in a separate dispatch:

| Artifact | Path | Change |
|---|---|---|
| AsyncAPI spec | `docs/arch/integrations/asyncapi/audit-and-oob.yaml` | Add `#OobChallengeEncryptedEnvelope` schema; update `OobChallengeIssued` message to split routing envelope from encrypted body |
| CUE schema | `docs/arch/schemas/access_mediation/oob_resolution.cue` | Add `#OobChallengeEncryptedEnvelope` definition with base64url field constraints |
| Gherkin feature | `docs/arch/specs/features/reveal_with_oob.feature` | Add scenarios: "OobChallenge decrypts only on enrolled device" and "OobChallenge denied when decryption fails" |
| TLA+ module | `docs/arch/formal/AEADNonceDiscipline.tla` | Optional: add ECIES nonce-discipline refinement |
| Sealed state schema | `docs/arch/schemas/identity_and_sealing/sealed_state.cue` | Add `x25519_public_key` field to `#EnrolledDevice` definition |

Cross-references:

* [0004-xchacha20-poly1305-aead-for-blobs.md](0004-xchacha20-poly1305-aead-for-blobs.md) —
  AEAD primitive (XChaCha20-Poly1305, 24-byte nonces, OsRng discipline) reused
  for ECIES inner encryption; nonce entropy gate applies equally here.
* [0007-handle-default-exposure-model.md](0007-handle-default-exposure-model.md) —
  Handle URI confidentiality model whose socket-layer gap this ADR closes; the
  `secret_handle` field is now encrypted end-to-end to the enrolled device.
* [0011-slash-only-reveal-with-oob-for-high-sensitivity.md](0011-slash-only-reveal-with-oob-for-high-sensitivity.md) —
  OOB Confirmation flow and enrollment ceremony that this ADR extends with an
  X25519 keypair; the Ed25519 signing keypair established in the Amendment
  remains unchanged.
* [0015-rust-keyring-crate-for-multi-os-keychain.md](0015-rust-keyring-crate-for-multi-os-keychain.md) —
  Companion Socket peer-credential authentication (first defense layer) that
  this ADR augments; the X25519 private key is stored in the same OS keychain
  entry `merkle-companion-<device-id>` as the Ed25519 private key.

Normative references:

* RFC 7748 — Elliptic Curves for Security (X25519, Curve25519, birational map
  §4.3).
* RFC 8032 — Edwards-Curve Digital Signature Algorithm (Ed25519).
* ECIES construction: ISO/IEC 18033-2 §10 (KEM-DEM hybrid encryption); this
  ADR uses X25519 as KEM and XChaCha20-Poly1305 as DEM with BLAKE3-KDF as
  the key derivation step.
* `x25519-dalek` crate: `https://crates.io/crates/x25519-dalek` — Rust
  implementation of X25519, RustCrypto ecosystem.
* `chacha20poly1305` crate: `https://crates.io/crates/chacha20poly1305` —
  XChaCha20-Poly1305 implementation, already in scope from ADR-0004.
* `blake3` crate: `https://crates.io/crates/blake3` — BLAKE3 KDF for shared
  secret expansion.
