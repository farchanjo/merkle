---
status: accepted
date: 2026-05-23
deciders: [farchanjo]
consulted: [Architecture, Security]
informed: [Engineering, SRE]
---

# 0020. Companion Device Hardware Class Policy

## Context and Problem Statement

ADR-0011 (Slash-Only Reveal with OOB Confirmation, Amendment 2026-05-22) establishes
the Companion Device as the cryptographic anchor for OOB Confirmation challenges.
The Companion Device signs every OOB challenge with an Ed25519 private key stored in
the OS keychain. Its role is singular: a `sensitivity=high` Reveal cannot complete
without a valid Ed25519 signature from an enrolled device.

The W4.B STRIDE expansion flagged the general-purpose smartphone as a residual risk.
A rogue application, a root exploit, or a malicious notification handler can capture
the Ed25519 signing key from a general-purpose OS keychain and auto-approve every
challenge without operator knowledge. A key held in a software keychain on a
compromised device is functionally exfiltrated even if it was never transmitted over
a network.

The current spec places no constraint on which device class may be enrolled.
Operators are free to pair any device that runs the `merkle-companion` agent,
regardless of whether the device provides hardware key isolation or per-challenge
user-presence enforcement. This creates a policy gap: the OOB Confirmation flow is
the last line of defense for `sensitivity=high` Reveals, yet the security properties
of that defense are entirely operator-dependent and unverifiable by the Vault Agent.

This ADR closes the gap by defining a `CompanionDeviceClass` enum, mapping each class
to an attestation mechanism verifiable at enrollment time, and establishing a
per-namespace policy field that the Rego authorization engine evaluates at every
Reveal decision.

## Decision Drivers

* **Defense against device compromise.** A rogue application, root exploit, or
  hostile OS update must not be sufficient to exfiltrate the signing key and silently
  auto-approve challenges. The chosen hardware class for `sensitivity=high` must
  provide a hardware isolation boundary that software cannot cross.
* **Hardware-backed key isolation.** The Ed25519 signing key must be generated inside
  and never exportable from a hardware security boundary: a Secure Enclave, a TPM 2.0,
  an ARM TrustZone-backed security processor, or a dedicated FIDO hardware security
  key with its own secure element.
* **Per-challenge user-presence enforcement.** The hardware must require a physical
  action (touch, biometric confirmation) before signing each challenge. Silent
  auto-approval must be architecturally impossible, not merely policy-prohibited.
* **Attestation chain availability.** The device must be able to present a
  cryptographically verifiable proof of its hardware class at enrollment time so that
  the Vault Agent can record the class in the audit chain without relying on
  self-declaration alone.
* **Open-source firmware availability.** For operators who require full supply-chain
  transparency, a hardware class that supports open-source firmware provides a
  defensive audit path. This driver constrains which hardware tokens are recommended
  but does not eliminate the class.
* **Operator UX friction.** A dedicated FIDO hardware security key requires the
  operator to carry a physical token and present it for every `sensitivity=high`
  Reveal. A smartphone with a Secure Enclave is more convenient but carries a broader
  attack surface. The policy must accommodate both, mapped to appropriate Sensitivity
  tiers.
* **Cost proportionality.** A dedicated hardware security key costs approximately
  $50 USD. For namespaces where `sensitivity=medium` is the ceiling, requiring a
  hardware token imposes disproportionate cost. The policy must allow
  `secure_enclave`-class devices for `medium` sensitivity while mandating
  `hardware_token` only where the threat model warrants it.
* **Tier-mapping flexibility.** Different namespaces warrant different device class
  requirements. Production credential namespaces differ from development namespaces.
  Operators must be able to configure the required class per namespace rather than
  enforcing a single global policy.

## Considered Options

* **Option A — Permissive (status quo).** Any device that runs the
  `merkle-companion` agent and can hold an Ed25519 key is acceptable. No hardware
  class enforcement. The operator is responsible for choosing a device with
  appropriate security properties.
* **Option B — Mandate hardware security key for all sensitivity tiers.** Reject
  general-purpose smartphones at enrollment regardless of sensitivity. Accepted
  devices: dedicated FIDO hardware security keys with an on-device secure element
  and manufacturer-signed attestation.
* **Option C — Mandate secure-enclave smartphone for all tiers.** Accepted
  hardware class: iOS devices with a Secure Enclave processor, Android devices with
  a dedicated security processor (Titan M2 or equivalent), Samsung devices with
  Knox Vault. General-purpose software keychains rejected. Dedicated hardware tokens
  also accepted as a strictly stronger class.
* **Option D — Tiered policy (chosen).** Per-namespace field
  `companion_device_class_required ∈ {software, secure_enclave, hardware_token}`
  on `#NamespacePolicy`. Sensitivity defaults: `high → hardware_token`,
  `medium → secure_enclave`, `low → software`. Operators may override per namespace.

## Decision Outcome

Chosen option: **Option D — Tiered policy**, because it aligns the required
hardware assurance with the existing Sensitivity gradation established in ADR-0011,
avoids disproportionate cost and friction for namespaces where `sensitivity=high`
secrets are not present, and provides a machine-enforceable policy field that the
Rego authorization engine can evaluate at every Reveal decision without operator
self-reporting.

The tiered design rests on three principles:

1. **Proportionality.** The OOB Confirmation for a `sensitivity=low` secret does not
   warrant the cost or friction of a dedicated hardware token. The class requirement
   scales with the impact of a compromised approval.
2. **Enforceability.** The class must be determined at enrollment time from a
   verifiable attestation chain, not from a device self-declaration. Downgrade events
   must be detectable and must require re-enrollment.
3. **Audit chain continuity.** The `device_class` field is recorded in the audit chain
   at enrollment. Every Reveal decision records which enrolled device signed the
   challenge, making the hardware class of the approval available for post-incident
   forensics.

### Device Class Enum

```
CompanionDeviceClass ∈ { software | secure_enclave | hardware_token }
```

| Class | Key isolation | User-presence | Attestation mechanism |
|---|---|---|---|
| `software` | OS keychain only (no hardware boundary) | Not enforced | Self-declaration; no cryptographic proof |
| `secure_enclave` | Secure Enclave / TPM 2.0 / ARM TrustZone | Biometric or PIN gate on every signing operation | OS platform attestation: iOS App Attest, Android Play Integrity API verdict, Windows TPM 2.0 endorsement key chain |
| `hardware_token` | Dedicated FIDO secure element | Physical touch required per signing operation | Manufacturer-signed FIDO attestation certificate chain rooted in the vendor's attestation CA |

The ordering `software < secure_enclave < hardware_token` defines a strict capability
hierarchy. A namespace that requires `secure_enclave` also accepts `hardware_token`.
The Rego policy evaluates `input.device.class_rank >= input.policy.required_class_rank`
where ranks are `software=0`, `secure_enclave=1`, `hardware_token=2`.

### Attestation Verification at Enrollment

The Vault Agent verifies the attestation chain at enrollment time (`merkle device pair`)
and records the resolved `device_class` in the Sealed State alongside the device's
Ed25519 public key. The attestation verification logic per class:

- **`software`:** No attestation required. The device declares its class in the
  enrollment request. The Vault Agent records `device_class = software` without
  verification. The operator bears full responsibility for the device's security
  posture.
- **`secure_enclave`:** The enrollment request MUST include an OS platform attestation
  artifact. On iOS, this is an App Attest assertion (CBOR-encoded, signed by the
  device's Secure Enclave key). On Android, this is a Play Integrity API verdict
  (`MEETS_DEVICE_INTEGRITY` or stronger). On Windows, this is a TPM 2.0 endorsement
  key certificate chain. The Vault Agent verifies the artifact against the platform's
  published root certificate. Failure to verify rejects enrollment.
- **`hardware_token`:** The enrollment request MUST include a FIDO attestation
  statement as defined in the W3C Web Authentication specification. The Vault Agent
  verifies the attestation certificate chain against the FIDO Metadata Service (FIDO
  MDS) or a locally pinned vendor attestation CA. Failure to verify rejects enrollment.

Attestation artifacts are stored in the audit chain for the `device_pair` event.
They are not re-verified on every challenge; re-verification occurs only at explicit
re-enrollment or when a `device_class_downgrade` event is detected.

### Namespace Policy Integration

A new field is added to `#NamespacePolicy`:

```
companion_device_class_required: #CompanionDeviceClass | *"secure_enclave"
```

The default is `secure_enclave`. Operators who require stronger assurance set
`hardware_token`; operators whose threat model tolerates software keys may set
`software`. The field is validated by the CUE schema at policy creation time.

Sensitivity-based defaults applied at namespace creation when no explicit value is
provided:

| Sensitivity ceiling | Default `companion_device_class_required` |
|---|---|
| `high` | `hardware_token` |
| `medium` | `secure_enclave` |
| `low` | `software` |

"Sensitivity ceiling" is the highest `sensitivity` value assigned to any Secret in
the namespace at the time of namespace creation. Operators may override the default
immediately after creation.

### Rego Enforcement Point

A new Rego policy `policies/companion_device_class.rego` evaluates the device class
constraint at every Reveal authorization decision. The policy is evaluated after the
OOB Confirmation signature verification in `sensitivity_oob.rego` and before the
rate-limit check in `rate_limit.rego`.

Decision rule:

```
deny[msg] {
    input.operation == "reveal"
    required_rank := class_rank[input.policy.companion_device_class_required]
    actual_rank   := class_rank[input.device.class]
    actual_rank < required_rank
    msg := {
        "denial_reason": "device_class_insufficient",
        "required_class": input.policy.companion_device_class_required,
        "actual_class":   input.device.class,
    }
}

class_rank := {
    "software":       0,
    "secure_enclave": 1,
    "hardware_token": 2,
}
```

`input.device.class` is populated by the Vault Agent from the `device_class` field
recorded in the Sealed State at enrollment time; it is not taken from the challenge
response payload and cannot be forged by the Companion Device at challenge time.

### Revocation and Downgrade Path

If a Companion Device's hardware security posture degrades — for example, a
smartphone receives a hostile OS update that compromises its Secure Enclave, or a
hardware token's firmware is found to have a critical vulnerability — the operator
MUST re-enroll the device:

1. `merkle device revoke <device-id>` removes the compromised device record from the
   Sealed State.
2. `merkle device pair` re-runs the enrollment ceremony with fresh attestation.
3. If the new attestation yields a lower `device_class` than the namespace requires,
   enrollment is rejected with `device_class_insufficient`.
4. The audit chain records a `device_class_downgrade_attempt` event with the old and
   new classes.

The revocation path is intentionally non-automated. A downgrade attempt must result
in an operator-visible rejection rather than a silent fallback to a weaker class.

### Interaction with ADR-0019 ECIES

Drafted in parallel with this ADR, ADR-0019 introduces an X25519 key for ECIES
transport encryption between the Vault Agent and the Companion Device, complementing
the existing Ed25519 signing key from ADR-0011. The enrollment ceremony for ADR-0019
(dual-key pairing) extends the `merkle device pair` flow. This ADR extends that
ceremony further by adding an `attestation_chain` field to the enrollment payload.

The combined enrollment payload contains:
- Ed25519 public key (signing, ADR-0011)
- X25519 public key (transport encryption, ADR-0019)
- `attestation_chain` (hardware class proof, this ADR)
- `device_class` (resolved by the Vault Agent from the attestation, this ADR)

All four fields are stored atomically in the Sealed State. The enrollment is
rejected if attestation verification fails; partial enrollment is not permitted.

### Consequences

* Good, because the `hardware_token` requirement for `sensitivity=high` closes the
  residual risk identified in the W4.B STRIDE expansion: a compromised smartphone OS
  cannot exfiltrate a key stored in a dedicated FIDO secure element.
* Good, because the tiered policy avoids imposing hardware token cost on
  `sensitivity=low` and `sensitivity=medium` namespaces where the threat model does
  not warrant it.
* Good, because the `device_class` is recorded in the audit chain at enrollment and
  referenced in every Reveal decision, making the hardware assurance level forensically
  observable without requiring per-challenge attestation.
* Good, because the Rego policy is the sole enforcement point; no application-layer
  code needs to be changed when an operator adjusts `companion_device_class_required`
  in a namespace policy.
* Bad, because `secure_enclave` attestation requires integration with three platform
  attestation APIs (iOS App Attest, Android Play Integrity, Windows TPM EK chain),
  each with vendor-specific SDKs, certificate root management, and revocation
  semantics. This is deferred to implementation but is non-trivial.
* Bad, because the `hardware_token` class depends on the FIDO Metadata Service for
  attestation root certificates. Operators in air-gapped environments must maintain
  a local attestation CA pinning configuration.
* Neutral, because the `software` class provides no additional security over the
  status quo. Its inclusion in the enum is intentional — it makes the lowest security
  tier a named, auditable choice rather than an undifferentiated default.

## Pros and Cons of the Options

### Option A — Permissive (status quo)

* Good, because no enrollment ceremony change is required; existing paired devices
  continue to work.
* Good, because the operator retains full control over device selection without
  enforcement friction.
* Bad, because the Vault Agent cannot distinguish a hardware-backed Companion Device
  from a software key on a compromised smartphone. The OOB Confirmation security
  property is entirely operator-dependent and unverifiable.
* Bad, because the W4.B STRIDE residual risk is left open: a rogue application with
  access to the OS keychain can exfiltrate the Ed25519 key and approve every
  challenge silently.
* Neutral, because many operators will choose hardware tokens anyway; Option A
  merely fails to enforce the choice or record it in the audit chain.

### Option B — Mandate hardware security key for all sensitivity tiers

* Good, because a dedicated FIDO secure element provides the strongest available
  key isolation across all sensitivity tiers. The attack surface is minimal: the
  key never leaves the secure element and signing requires physical touch.
* Good, because FIDO attestation is a well-specified, widely deployed mechanism;
  verification libraries exist for Rust.
* Bad, because mandating a hardware token for `sensitivity=low` and
  `sensitivity=medium` namespaces imposes $50 USD cost and physical-token UX on
  operations whose threat model does not require it. This is likely to drive
  operators to avoid sensitivity classification altogether.
* Bad, because hardware tokens cannot enroll without physical presence; remote
  or headless deployment scenarios require workflow accommodations that are
  currently undefined.
* Neutral, because Option B is a valid choice for high-security deployments; it is
  available as a namespace-level configuration in Option D.

### Option C — Mandate secure-enclave smartphone for all tiers

* Good, because smartphones are already carried by operators; the UX burden is
  lower than a dedicated hardware token.
* Good, because Secure Enclave and equivalent hardware processors provide genuine
  key isolation against software attacks and most physical attacks.
* Bad, because smartphone OS updates remain a risk vector. A hostile update that
  compromises the Secure Enclave bridge, the biometric subsystem, or the platform
  attestation infrastructure can bypass key isolation in ways that dedicated FIDO
  hardware cannot.
* Bad, because platform attestation (iOS App Attest, Android Play Integrity) is
  controlled by Apple and Google respectively. Changes to their attestation policies
  can silently break enrollment for all enrolled devices.
* Bad, because open-source firmware is not available for mainstream smartphone
  Secure Enclaves, limiting supply-chain audit coverage for high-assurance operators.
* Neutral, because Option C is a valid choice for most operators and is available
  as the `secure_enclave` class in Option D.

### Option D — Tiered policy (chosen)

* Good, because it maps hardware assurance to Sensitivity tier, matching the
  existing gradation from ADR-0011 and avoiding over-enforcement on lower tiers.
* Good, because it is fully machine-enforceable through the Rego policy; the
  operator's device class choice is recorded and auditable, not just advisory.
* Good, because it allows operators to upgrade a namespace's required class
  independently of other namespaces, enabling incremental hardening.
* Bad, because three attestation verification code paths (iOS, Android, Windows
  TPM, FIDO hardware) must be implemented and maintained. This is the largest
  single implementation cost of this ADR.
* Neutral, because the `software` class preserves backward compatibility with the
  status quo for operators who explicitly accept the lower assurance level.

## Validation

- New CUE definition `#CompanionDeviceClass: "software" | "secure_enclave" | "hardware_token"`
  in `docs/arch/schemas/policy_permissions/namespace_policy.cue`. Field
  `companion_device_class_required: #CompanionDeviceClass | *"secure_enclave"` added
  to `#NamespacePolicy`.
- New Rego policy `docs/arch/policies/companion_device_class.rego` implementing the
  `deny` rule with `class_rank` map.
- New Rego test file `docs/arch/policies/companion_device_class_test.rego` with
  test cases:
  - `test_deny_software_device_on_hardware_token_policy`
  - `test_deny_software_device_on_secure_enclave_policy`
  - `test_allow_secure_enclave_device_on_secure_enclave_policy`
  - `test_allow_hardware_token_device_on_hardware_token_policy`
  - `test_allow_hardware_token_device_on_secure_enclave_policy` (stronger class accepted)
  - `test_allow_software_device_on_software_policy`
- New Gherkin scenarios appended to
  `docs/arch/specs/features/reveal_with_oob.feature`:
  - `Reveal denied when device class below policy minimum` — enrolls `software`
    device; namespace requires `secure_enclave`; assert `device_class_insufficient`.
  - `Reveal allowed when device class meets minimum` — enrolls `secure_enclave`
    device; namespace requires `secure_enclave`; assert reveal succeeds.
  - `Reveal allowed when device class exceeds minimum` — enrolls `hardware_token`
    device; namespace requires `secure_enclave`; assert reveal succeeds.
- AsyncAPI `OobChallenge` channel MAY expose a `device_class_required` informational
  field so the Companion Device can adapt its UX (for example, prompting for touch on
  a hardware token when the namespace requires `hardware_token`). The authorization
  decision itself is server-side; this field is advisory only.
- `spec validate --lane full` exits 0 with `lint_madr 20/20 passed`.

## More Information

Cross-references:

* [0007-handle-default-exposure-model.md](0007-handle-default-exposure-model.md) —
  the Handle exposure model that establishes Reveals as the primary secret-exposure
  risk, motivating the hardware class constraint on the last line of defense.
* [0011-slash-only-reveal-with-oob-for-high-sensitivity.md](0011-slash-only-reveal-with-oob-for-high-sensitivity.md) —
  the OOB Confirmation and Companion Device enrollment ceremony this ADR extends.
  ADR-0011 Amendment defines the Ed25519 signing protocol; this ADR constrains the
  hardware class of the device that holds the signing key.
* [0015-rust-keyring-crate-for-multi-os-keychain.md](0015-rust-keyring-crate-for-multi-os-keychain.md) —
  keychain integration used by the `software` class to store the Ed25519 private key.
  The `secure_enclave` and `hardware_token` classes bypass the OS keychain in favor
  of hardware-isolated key storage; this ADR's policy makes that distinction
  enforceable.
* ADR-0019 — ECIES transport encryption for Companion Device communication.
  Drafted in parallel with this ADR. The dual-key enrollment ceremony in ADR-0019
  is extended by the `attestation_chain` field introduced here.

Follow-up implementation artifacts (not authored in this ADR):

| Artifact | Path | Notes |
|---|---|---|
| `#CompanionDeviceClass` CUE enum | `docs/arch/schemas/policy_permissions/namespace_policy.cue` | Add enum definition and field to `#NamespacePolicy` |
| Companion device class Rego policy | `docs/arch/policies/companion_device_class.rego` | Deny rule with `class_rank` map |
| Companion device class Rego tests | `docs/arch/policies/companion_device_class_test.rego` | Six test cases listed in Validation |
| Gherkin device class scenarios | `docs/arch/specs/features/reveal_with_oob.feature` | Three new scenarios listed in Validation |
| AsyncAPI `OobChallenge` update | `docs/arch/integrations/asyncapi/audit-and-oob.yaml` | Add informational `device_class_required` field |
| Sealed State schema update | `docs/arch/schemas/identity_and_sealing/sealed_state.cue` | Add `device_class` field to enrolled device record |

The ADR-0011 `## More Information` section should receive a cross-reference to this ADR
when next amended (tracked as a follow-up to avoid an out-of-scope edit here).
