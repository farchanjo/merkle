---
status: accepted
date: 2026-05-22
deciders: [farchanjo]
consulted: []
informed: []
---

# 0006. age Encryption for Backups and Recovery Key

## Context and Problem Statement

Merkle generates periodic Backups: single-file exports of the entire
vault state that must be safe to store in untrusted locations (cloud
storage, USB drive, email) and must be recoverable even if the OS
keychain is wiped. The backup format must support multiple recipients
(so the backup is independently accessible via the Master Key and the
Recovery Key), be producible and parseable by pure-Rust code without
external binaries, and resist future quantum threats via a clear
upgrade path.

The Recovery Key itself is an `age` identity (X25519 secret key)
displayed exactly once at `merkle init`. It must be in a format the
operator can copy to paper, store in a password manager, or print
as a QR code. The format must be unambiguous and self-describing.

## Decision Drivers

* Two-recipient encryption: every backup must be decryptable by
  either the Master public key or the Recovery Public Key independently.
* Pure-Rust implementation: no dependency on the `age` binary; the
  `age` crate (`https://crates.io/crates/age`) implements the full
  format in Rust.
* Modern UX: the `age` format is minimal, human-readable for
  identity files, and does not require a keyring or keyserver.
* Avoids PGP complexity: no web of trust, no subkey management, no
  expiry dates to track.
* X25519 recipients: Diffie-Hellman key agreement with modern
  elliptic curves; 32-byte public keys that can be printed
  compactly.
* Backup file self-description: the `age` header contains recipient
  stanzas that identify which keys can decrypt; no out-of-band
  metadata required.
* `age` version 1 format is finalized and public:
  `https://age-encryption.org/v1`.

## Considered Options

* Option A: `age` (filippo.io/age) with two recipients
* Option B: PGP (OpenPGP, RFC 4880) with two recipients
* Option C: OpenSSL symmetric encryption (AES-256-CBC or AES-256-GCM)
* Option D: Google Tink

## Decision Outcome

Chosen option: "Option A: age with two recipients", because `age`
was designed specifically for file encryption with multiple
recipients, has a finalized and minimal format specification, is
available as a pure-Rust crate, and uses X25519 + ChaCha20-Poly1305
internally (consistent with the rest of Merkle's cipher choices).

Every backup is encrypted with exactly two recipient stanzas: the
Master public key (derived from the Master Key at unseal time) and
the Recovery Public Key (stored in plaintext in `config.toml`). The
resulting `.merkle.age` file is decodable by either key
independently, enabling both routine restore and disaster recovery
without any coordination.

### Consequences

* Good, because `age`'s two-recipient model is built into the format;
  adding or removing a recipient requires re-encrypting the file key,
  not the entire payload.
* Good, because the Recovery Key is in `age` identity format: a
  50-character `AGE-SECRET-KEY-1...` string that is easy to print,
  store offline, and verify by checksum.
* Good, because the `age` crate implements the full format without
  shelling out to the `age` binary; no external process dependency.
* Good, because `age` v1 uses X25519 for key agreement and
  ChaCha20-Poly1305 for payload encryption, consistent with the
  cipher choices in
  [0004-xchacha20-poly1305-aead-for-blobs.md](0004-xchacha20-poly1305-aead-for-blobs.md).
* Bad, because `age` does not yet have a finalized post-quantum
  recipient type; if the project needs PQ resistance, a second KEM
  layer (ML-KEM / CRYSTALS-Kyber) would need to be wrapped around
  the `age` payload. This is a known limitation accepted for the
  current threat model.
* Bad, because the `age` format does not support signing; a separate
  BLAKE3 HMAC is applied to the backup file to authenticate
  provenance (not covered by `age` itself).

## Pros and Cons of the Options

### Option A: age with two recipients

* Good: designed for multi-recipient file encryption; minimal format.
* Good: pure Rust; no external binary.
* Good: human-readable identity files for offline key storage.
* Good: X25519 + ChaCha20-Poly1305 consistent with Merkle's cipher stack.
* Bad: no native post-quantum recipient type yet.
* Bad: no built-in signing; requires external HMAC.

### Option B: PGP (OpenPGP, RFC 4880)

* Good: ubiquitous; hardware token support (YubiKey).
* Bad: format complexity is enormous; subkey management, expiry
  dates, web of trust, and keyserver dependencies create operational
  risk for a local-first tool.
* Bad: the Rust `sequoia-openpgp` crate is large and heavy; adds
  significant compile time and binary size.
* Bad: operator UX for managing two PGP recipients and their subkeys
  is far more complex than `age`.

### Option C: OpenSSL symmetric encryption

* Good: simple; single passphrase.
* Bad: no multi-recipient support; sharing the backup requires
  sharing the passphrase.
* Bad: no asymmetric key material for disaster recovery without
  knowing the passphrase at restore time.
* Bad: requires the `openssl` binary or `openssl` crate with C FFI.

### Option D: Google Tink

* Good: multi-language; audited.
* Bad: no multi-recipient file format designed for backup use cases.
* Bad: Rust support is experimental and not production-ready.
* Bad: significantly more complex API surface than `age`.

## Validation

* Round-trip test: create a backup with two recipients; decrypt with
  the Master public key; decrypt with the Recovery Key; assert both
  produce identical plaintext.
* Disaster recovery test: lose the Master Key (mock keychain wipe);
  restore using only the Recovery Key identity file; assert vault
  state is fully recovered.
* Identity format test: parse the Recovery Key identity string;
  assert `age` recipient type is `X25519` and checksum validates.
* HMAC test: corrupt one byte in the `.merkle.age` file after
  decryption; assert the BLAKE3 HMAC check fails before any data is
  applied.

## More Information

* age v1 format specification: `https://age-encryption.org/v1`.
* `age` crate: `https://crates.io/crates/age`.
* `rage` (Rust implementation reference): `https://github.com/str4d/rage`.
* Related: [0004-xchacha20-poly1305-aead-for-blobs.md](0004-xchacha20-poly1305-aead-for-blobs.md)
* Related: [0009-merkle-style-audit-hash-chain.md](0009-merkle-style-audit-hash-chain.md)
* Related: [0010-anacron-style-backup-triggers.md](0010-anacron-style-backup-triggers.md)

## Amendment — 2026-05-22

### HMAC Key Compartmentalization

The backup HMAC is keyed with the Vault HMAC Key, which is a distinct key from the
Master Key, Vault Root Key, and all Namespace DEKs. The Vault HMAC Key is derived
from the Master Key using BLAKE3 in keyed-derivation mode:

```
vault_hmac_key = BLAKE3(key=master_key, data="merkle:vault-hmac-key:v1")
```

This derivation MUST be performed at unseal time and stored in the agent's
`mlocked` key store. The Vault HMAC Key is never written to disk in plaintext.
Using a derived key rather than the Master Key directly ensures that compromise of
the HMAC key (e.g., via a side-channel in the HMAC computation path) does not
directly expose the Master Key or any DEK.

### Encrypt-then-MAC (mandatory)

The HMAC is applied to the age ciphertext after encryption (encrypt-then-MAC). The
HMAC input is the entire `.merkle.age` file content as written to disk, with no
framing additions. The 32-byte BLAKE3 HMAC tag is appended to the file as a fixed-
length trailer. On restore, the HMAC MUST be verified before age decryption begins;
a tag mismatch MUST cause the restore to abort with an error before any decryption
is attempted.

The previous `Validation` section noted a HMAC test over plaintext; that test SHALL
be updated to verify the HMAC over the ciphertext (the full `.merkle.age` file
content before the trailer) rather than the decrypted payload.

### Master Key Rotation Impact on Old Backups

When the Master Key is rotated (`merkle key-rotate`), old backup files remain
encrypted for the old Master public key (derived from the pre-rotation Master Key).
After rotation:

- Old backups are decryptable using the old Master private key material. Because the
  Vault Root Key was re-wrapped with the new Master Key, the old Master private key
  is no longer held in the keychain; however, it was the derivation of the Master
  Key's corresponding age identity.
- Old backups are always decryptable using the Recovery Key (the age identity
  displayed at `merkle init`). The Recovery Key is not rotated by `merkle
  key-rotate`.
- This means an operator who loses the Recovery Key after a Master Key rotation has
  no path to restore from a pre-rotation backup using only the current Master Key.

**Accepted residual risk:** the inability to restore a pre-rotation backup without
the Recovery Key is accepted. Operators MUST store the Recovery Key durably offline.
The `merkle key-rotate` command MUST print an explicit warning to this effect and
require the operator to acknowledge it before proceeding.

### `merkle verify-recovery-key` Command

The command `merkle verify-recovery-key` SHALL accept either an inline identity
string (`AGE-SECRET-KEY-1...`) or a path to an identity file. It verifies that:

1. The identity parses as a valid `age` X25519 secret key.
2. The corresponding X25519 public key matches the Recovery Public Key stored in
   `config.toml`.
3. (Optional, with `--smoke-test`) A small test payload is encrypted for the
   Recovery Public Key and successfully decrypted with the provided identity.

The command returns exit code 0 on success, exit code 1 on any verification
failure, and emits a `recovery_key_verified` audit entry. It does not modify any
vault state.

Cross-reference: [0004-xchacha20-poly1305-aead-for-blobs.md](0004-xchacha20-poly1305-aead-for-blobs.md),
[0009-merkle-style-audit-hash-chain.md](0009-merkle-style-audit-hash-chain.md).

## Amendment 2 — 2026-05-22

### Recovery Key Generation Algorithm

The Recovery Key is generated at `merkle init` using the following procedure:

1. Draw 32 bytes of cryptographically secure random data from `OsRng`
   (from `rand_core::OsRng`; backed by `getrandom`, which delegates to
   `getentropy` / `BCryptGenRandom` depending on the platform). This is the
   X25519 secret scalar.
2. Construct an `age` X25519 identity from the 32-byte seed using the `age`
   crate (`https://crates.io/crates/age`). The `age` crate derives the
   corresponding public key and encodes both according to the `age` v1 format.
3. The identity is encoded as a Bech32 string with the human-readable part
   `AGE-SECRET-KEY-1`. The resulting string is exactly 74 characters in the
   uppercase Bech32 encoding mandated by the `age` v1 specification.

The Recovery Key string format is `AGE-SECRET-KEY-1<bech32-data>` (all
uppercase). Example shape (not a real key):

```
AGE-SECRET-KEY-1QPZGY5ALPTEA98WKNQVSQVXJVZRLMRM2YQPZGY5ALPTEA98WKNQVS
```

The corresponding Recovery Public Key is derived by the `age` crate from the
secret key and stored in plaintext in `config.toml` under the field
`recovery_pubkey`. The Recovery Key is never written to disk or to any
persistent store by the Merkle system.

### Display and Recording Protocol

The Recovery Key is displayed exactly once — immediately after generation
during the `merkle init` wizard (Step 5 of the onboarding flow). The display
MUST:

1. Print the full `AGE-SECRET-KEY-1...` string to the operator's terminal.
2. Frame the output with a visible warning banner instructing the operator to
   record the key offline before proceeding.
3. Require the operator to re-enter the first four words of the Recovery Key
   as a confirmation of recording (Step 6 of the onboarding flow). The wizard
   MUST NOT proceed until the re-entry matches.

After the wizard proceeds, the Recovery Key is no longer accessible through
any Merkle command. The system stores only the Recovery Public Key.

### Re-Enrollment Path (Loss Before Any Backup)

If an operator loses the Recovery Key before any Backup has been created, the
following applies:

- There is no re-enrollment path that preserves the existing vault. The
  Recovery Key is not stored by the system and cannot be regenerated from any
  persisted material.
- The operator MUST reinitialize the vault (`merkle init` on a fresh
  installation) to obtain a new Recovery Key and a new vault identity.
- Any secrets already stored in the lost vault are unrecoverable without the
  Recovery Key or the OS Keychain holding the Master Key. If the OS Keychain
  is still intact, the operator may use `merkle rekey` to generate a new
  Recovery Key and re-encrypt the vault state.

**Accepted constraint:** the inability to re-display or re-issue the Recovery
Key is a deliberate design choice. Storing the Recovery Key would create a
second attack surface. Operators MUST record the Recovery Key offline at init
time; there is no second chance.

### `merkle verify-recovery-key` — Secure Input and State Contract

The `merkle verify-recovery-key` command (introduced in Amendment 1) MUST
observe the following additional constraints:

1. **Secure TTY input.** When the operator does not supply an `--identity-file`
   path, the command reads the Recovery Key interactively from the controlling
   TTY using the `rpassword` crate (`https://crates.io/crates/rpassword`).
   The `rpassword` crate disables terminal echo before reading, ensuring the
   secret key string is never displayed in the terminal scroll buffer. Piped
   input (`echo "AGE-SECRET-KEY-1..." | merkle verify-recovery-key`) MUST be
   rejected with an error; the command requires an interactive TTY or an
   explicit `--identity-file` flag.

2. **No state modification.** The command reads `recovery_pubkey` from
   `config.toml` and the current agent state, but MUST NOT modify any vault
   state, write to the database, or alter any key material. The only permitted
   side-effect is the `recovery_key_verified` audit entry (per Amendment 1).

3. **Return values.** Exit code 0 indicates the provided key matches the stored
   Recovery Public Key. Exit code 1 indicates any verification failure
   (parse error, key mismatch, or smoke-test decryption failure). The command
   MUST print a human-readable result line (`ok` or `mismatch: <reason>`) to
   stdout. Detailed diagnostics go to stderr.

### Vault Operator Verification Requirement

The Vault Operator MUST run `merkle verify-recovery-key` during the initial
unseal flow — after the agent reaches Unsealed State but before any secrets are
created. This requirement exists to confirm that the recorded Recovery Key
matches the `recovery_pubkey` stored in `config.toml` while the vault is still
empty and recovery is trivially available.

The `merkle doctor` command MUST check whether `verify-recovery-key` has been
run at least once (as evidenced by the `recovery_key_verified` audit entry) and
emit a `WARN: recovery key not yet verified` diagnostic if no such entry exists.

Cross-reference: [0005-argon2id-kdf-for-passphrase-fallback.md](0005-argon2id-kdf-for-passphrase-fallback.md),
[0004-xchacha20-poly1305-aead-for-blobs.md](0004-xchacha20-poly1305-aead-for-blobs.md),
[0009-merkle-style-audit-hash-chain.md](0009-merkle-style-audit-hash-chain.md),
[0015-rust-keyring-crate-for-multi-os-keychain.md](0015-rust-keyring-crate-for-multi-os-keychain.md).

## Amendment — 2026-07-01

### Recovery Identity Is Operator-Supplied, Not Agent-Generated

This amendment supersedes the "Amendment 2 — Recovery Key Generation
Algorithm" mechanism above. That amendment had the agent draw 32 bytes from
`OsRng` at `merkle init`, construct the `age` X25519 identity itself, and
display the `AGE-SECRET-KEY-1…` secret to the operator exactly once. In the
shipped design the agent never generates or displays a recovery secret key.

**Corrected model (mandatory):** the operator PRE-GENERATES the `age` recovery
identity out-of-band and holds the private half themselves. Only the
recipient (a real `age1…` X25519 recipient) is supplied to the agent, via
`MERKLE_RECOVERY_RECIPIENT` (required at startup; placeholders are rejected).
At init the `wrapped_by = "recovery"` copy of the Vault Root Key is produced
by `age`-encrypting the VRK under that operator-supplied recipient, and the
`recovery_key` returned by init merely echoes that same recipient — it is not
a freshly minted secret.

Consequences for text above:
- The `OsRng`-draw / identity-construction / secret-display procedure in
  Amendment 2 no longer applies; the agent stores no recovery secret and has
  none to display.
- The `recovery_pubkey` in `config.toml` and the recipient echoed by init are
  the operator's own recipient, not a value the agent derived.
- Disaster recovery is unchanged in intent: the VRK remains recoverable via
  the operator-held private identity if the OS Keychain or Master Key is lost.
- `merkle verify-recovery-key` (Amendment 1) still applies: it confirms the
  operator-held identity matches the stored recipient.

Cross-reference: [0021-init-vault-bootstrap-ceremony.md](0021-init-vault-bootstrap-ceremony.md)
Amendment — 2026-07-01,
[0004-xchacha20-poly1305-aead-for-blobs.md](0004-xchacha20-poly1305-aead-for-blobs.md),
[0015-rust-keyring-crate-for-multi-os-keychain.md](0015-rust-keyring-crate-for-multi-os-keychain.md).
