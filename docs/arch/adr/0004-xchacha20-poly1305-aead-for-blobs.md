---
status: accepted
date: 2026-05-22
deciders: [farchanjo]
consulted: []
informed: []
---

# 0004. XChaCha20-Poly1305 AEAD for Blob Encryption

## Context and Problem Statement

Every Secret's `private_blob` column must be encrypted at rest using
an authenticated cipher that detects tampering (AEAD). The cipher
choice must be: available as a pure-Rust crate with no unreviewed C
FFI, use nonces long enough to safely generate randomly without
collision risk across millions of secrets in a long-lived vault, and
authenticate the ciphertext so that any corruption or modification is
detected on decrypt.

The nonce collision threat is concrete: a 96-bit (12-byte) nonce,
generated uniformly at random, reaches a collision probability of
roughly 50% at 2^48 messages under the birthday bound. A vault used
continuously for years with automatic rotation could exceed that
threshold. Switching from a 12-byte to a 24-byte nonce eliminates
the risk entirely.

## Decision Drivers

* AEAD: ciphertext authentication is mandatory; unauthenticated
  encryption is not acceptable for this use case.
* Nonce length: 24-byte (192-bit) nonces make random-nonce collision
  probability negligible across the lifetime of the vault.
* Pure-Rust implementation: no C FFI in the encryption hot path; the
  `chacha20poly1305` crate from the `RustCrypto` organization is
  audited and widely used.
* Per-blob nonces: each blob gets its own randomly generated nonce,
  prefixed to the ciphertext. Loss of one blob's nonce is catastrophic
  for that blob only.
* Hardware acceleration: ChaCha20 is fast on platforms without AES-NI
  (common embedded and ARM targets); on x86_64 with AES-NI, AES-GCM
  is faster but the speed difference is not material for this workload.
* Associated Data (AD): the Handle (namespace UUID + category + name)
  is bound as associated data, so a ciphertext cannot be moved to a
  different row without authentication failure.

## Considered Options

* Option A: XChaCha20-Poly1305 (24-byte nonces)
* Option B: ChaCha20-Poly1305 (12-byte nonces, RFC 8439)
* Option C: AES-256-GCM (12-byte nonces)
* Option D: AES-256-GCM-SIV (nonce-misuse resistant)

## Decision Outcome

Chosen option: "Option A: XChaCha20-Poly1305", because the 24-byte
nonce eliminates birthday-bound collision risk entirely when nonces
are generated uniformly at random per blob, without requiring a
counter or state machine to ensure nonce uniqueness. The
`chacha20poly1305` crate's `XChaCha20Poly1305` type implements this
variant directly.

The Handle (URI string) is included as AEAD associated data on every
encrypt and decrypt call, binding ciphertext to its identity and
preventing ciphertext transplantation between rows.

### Consequences

* Good, because 24-byte nonces generated via `OsRng` have a
  collision probability below 2^(-80) across 10^12 blobs, far
  exceeding the expected lifetime volume of any single vault.
* Good, because the `chacha20poly1305` crate is a `RustCrypto`
  project with a published security audit; no C FFI.
* Good, because binding the Handle as associated data means
  row-swapping attacks (copy one secret's ciphertext to another row)
  are detected at decrypt time.
* Good, because the cipher works efficiently on all target platforms
  including ARM macOS (M-series) without requiring AES-NI.
* Bad, because XChaCha20-Poly1305 is slightly less common than
  AES-256-GCM in compliance documentation; some regulatory frameworks
  name AES-256-GCM explicitly. This is not a current concern for
  Merkle's threat model but may require documentation if the project
  enters regulated environments.

## Pros and Cons of the Options

### Option A: XChaCha20-Poly1305 (24-byte nonces)

* Good: 24-byte nonces; negligible collision probability with random
  generation; no nonce management state required.
* Good: pure Rust, audited `RustCrypto` implementation.
* Good: fast on ARM without hardware AES acceleration.
* Bad: less common in compliance literature than AES-256-GCM.

### Option B: ChaCha20-Poly1305 (12-byte nonces, RFC 8439)

* Good: IETF standard; widely reviewed; same crate family.
* Bad: 12-byte nonces; birthday bound collision risk at 2^48 messages
  requires a nonce counter or KDF-derived nonces per write, adding
  state management complexity.
* Bad: for a vault that may store millions of entries over years, the
  collision probability is non-negligible without careful counter
  management.

### Option C: AES-256-GCM (12-byte nonces)

* Good: NIST-approved; hardware acceleration via AES-NI on x86_64.
* Bad: 12-byte nonces; same birthday-bound issue as Option B.
* Bad: slower on ARM without hardware acceleration (common developer
  laptops in 2024+).
* Bad: requires `aes-gcm` crate; acceptable but adds a second crypto
  primitive to the dependency tree unnecessarily.

### Option D: AES-256-GCM-SIV (nonce-misuse resistant)

* Good: nonce-misuse resistant; safe even if nonces repeat.
* Bad: less widely deployed; the `aes-gcm-siv` crate has a smaller
  review surface.
* Bad: nonce-misuse resistance adds complexity that is not needed
  when nonces are generated per-blob via `OsRng`; the protection is
  solving a problem Merkle does not have.
* Bad: performance on ARM is similar to AES-256-GCM; no advantage
  over Option A on the target hardware profile.

## Validation

* Property test: generate 10^6 random nonces; assert zero collisions
  (probabilistic safety check; failure would indicate a broken RNG).
* Tamper detection test: flip one byte in a stored `private_blob`;
  assert that decrypt returns an `AeadError`.
* AD binding test: decrypt a ciphertext using the Handle of a
  different Secret as associated data; assert authentication failure.
* Interoperability test: encrypt with the `chacha20poly1305` crate;
  decrypt with a reference Python implementation using
  `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`
  (with a 24-byte nonce prefix stripped for the X variant).

## More Information

* RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols.
* `libsodium` XChaCha20-Poly1305 specification (reference for
  extended-nonce construction).
* `chacha20poly1305` crate: `https://crates.io/crates/chacha20poly1305`.
* RustCrypto audit report: `https://research.nccgroup.com/`.
* Related: [0003-sqlite-with-per-blob-encryption.md](0003-sqlite-with-per-blob-encryption.md)
* Related: [0005-argon2id-kdf-for-passphrase-fallback.md](0005-argon2id-kdf-for-passphrase-fallback.md)

## Amendment — 2026-05-22

### Associated Data Binding (mandatory)

Every blob encryption call MUST pass the Handle URI as Associated Data (AD) to
`XChaCha20Poly1305::encrypt_in_place_detached`. The Handle URI is the canonical
string form `vault://<namespace>/<category>/<name>` stored in the `handle` column
of the same row.

Decryption MUST supply the same Handle URI as AD. If the AD supplied at decrypt
time does not match the AD bound at encrypt time, the Poly1305 authentication tag
verification fails and the call returns `AeadError`. The agent MUST treat this
failure identically to a corrupted ciphertext: emit a `blob_integrity_failed` audit
entry and return an error to the caller. There is no fallback path.

This codifies the existing design note in the Decision Drivers section as a hard
invariant: the implementation is not compliant unless AD binding is exercised on
every encrypt and every decrypt call. A ciphertext that was encrypted without AD
cannot be decrypted with AD, and vice versa; migration of any pre-AD blob MUST
re-encrypt with the correct AD before the invariant is considered satisfied.

### Nonce-Reuse Detection at Boot (mandatory)

`OsRng` from `rand_core` is the sole source of nonce material. Before the first
encryption call in any agent session, the following entropy gate MUST be applied:

1. On Linux, read `/proc/sys/kernel/random/entropy_avail`. If the value is below
   128, the agent MUST refuse to start encryption and emit a fatal error
   `ENTROPY_UNAVAILABLE`. The threshold of 128 is conservative; Linux 5.18+
   guarantees `getrandom(2)` blocks until the CRNG is initialised, making this
   check a belt-and-suspenders guard for older kernels.
2. On all platforms, if `getrandom(GRND_INSECURE)` is the only path available
   (kernel older than 3.17 or a seccomp policy that blocks `getrandom`), the agent
   MUST halt with a fatal error rather than proceeding with a potentially
   non-cryptographic random source.
3. macOS and Windows use OS-provided CSPRNG APIs (`SecRandomCopyBytes` /
   `BCryptGenRandom`) via the `rand_core::OsRng` abstraction; these APIs block
   internally until the system RNG is seeded. A failure return from those APIs MUST
   be propagated as a fatal error, not silently retried.

The rationale: a nonce collision under XChaCha20-Poly1305, while astronomically
unlikely with a correctly seeded CSPRNG, would allow an attacker who observes two
ciphertexts with the same nonce to XOR-cancel the keystream and recover the XOR of
both plaintexts. Halting is the correct response to RNG failure; producing a weak
nonce is not acceptable.

Cross-reference: [0003-sqlite-with-per-blob-encryption.md](0003-sqlite-with-per-blob-encryption.md),
[0005-argon2id-kdf-for-passphrase-fallback.md](0005-argon2id-kdf-for-passphrase-fallback.md),
[0018-full-coverage-validation-as-architectural-contract.md](0018-full-coverage-validation-as-architectural-contract.md) — the TLA+
AEAD nonce-uniqueness spec formally verifies the nonce discipline established
in this ADR.
