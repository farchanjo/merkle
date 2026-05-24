---
status: accepted
date: 2026-05-22
deciders: [farchanjo]
consulted: []
informed: []
---

# 0005. Argon2id KDF for Passphrase Fallback

## Context and Problem Statement

The Master Key is normally stored in the OS keychain abstracted by
the `keyring` crate (see
[0015-rust-keyring-crate-for-multi-os-keychain.md](0015-rust-keyring-crate-for-multi-os-keychain.md)).
On systems where no keychain backend is available (headless Linux
servers, CI environments, containers), Merkle must fall back to
deriving the Master Key from a user-supplied passphrase.

This derived key must be resistant to brute-force and dictionary
attacks. A weak or fast KDF (PBKDF2 with SHA-256, or bcrypt) can be
attacked with commodity GPU hardware. The chosen KDF must be
memory-hard to neutralize GPU and ASIC parallelism, and must be
resistant to timing side-channels.

The KDF is also used at `merkle init` to generate the wrapped Master
Key for the passphrase-fallback path, and optionally during key
rotation.

## Decision Drivers

* Memory-hard: the KDF must require a configurable amount of RAM
  per invocation, making GPU parallelism economically unviable.
* Side-channel resistant: the KDF must not exhibit data-dependent
  timing (i.e., it must be resistant to cache-timing attacks).
* RFC standardized: the implementation must follow a published
  standard to allow interoperability and independent review.
* Password Hashing Competition (PHC): the algorithm must be the PHC
  winner to ensure it has been vetted by the academic community.
* Pure-Rust crate availability: `argon2` from the `RustCrypto`
  organization implements RFC 9106 and is audited.
* Configurable parameters: `m_cost` (memory), `t_cost` (iterations),
  `p_cost` (parallelism) must be tunable to adjust hardness over time.

## Considered Options

* Option A: Argon2id (RFC 9106) — hybrid variant
* Option B: scrypt (RFC 7914)
* Option C: bcrypt
* Option D: PBKDF2-SHA256 (RFC 8018)

## Decision Outcome

Chosen option: "Option A: Argon2id (RFC 9106)", because it is the
Password Hashing Competition winner, is standardized in RFC 9106,
provides both memory-hardness and side-channel resistance via its
hybrid Argon2i (data-independent) + Argon2d (data-dependent) design,
and is implemented in the `argon2` crate without C FFI.

Default parameters at `merkle init`: `m_cost = 65536` (64 MiB),
`t_cost = 3`, `p_cost = 4`. These may be tightened by the operator
via the Security Profile.

### Consequences

* Good, because Argon2id's memory-hardness neutralizes GPU and ASIC
  attacks; 64 MiB per invocation is prohibitively expensive in
  parallel.
* Good, because the data-independent memory access pattern of the
  Argon2i pass protects against side-channel cache-timing attacks,
  while the Argon2d pass provides GPU resistance.
* Good, because RFC 9106 standardization enables independent
  cryptographic review and future interoperability.
* Good, because parameters are stored in the database alongside the
  salt and wrapped Master Key; upgrading parameters at next unseal
  is straightforward.
* Bad, because Argon2id is slower than PBKDF2 or bcrypt by design;
  the passphrase prompt adds ~300 ms on reference hardware. This is
  acceptable for an interactive unseal but not for automated CI.
* Bad, because in the CI / headless path the operator must supply
  the passphrase via environment variable; the security of the
  derived key then depends on the secrecy of that variable. This is
  documented as a known limitation of the passphrase-fallback path.

## Pros and Cons of the Options

### Option A: Argon2id (RFC 9106)

* Good: PHC winner; RFC standardized; pure-Rust audited crate.
* Good: memory-hard AND side-channel resistant (hybrid design).
* Good: configurable m/t/p parameters; future-proof.
* Bad: slower than alternatives; ~300 ms at recommended parameters.

### Option B: scrypt (RFC 7914)

* Good: memory-hard; widely deployed (used by WireGuard, macOS).
* Bad: not the PHC winner; no equivalent of Argon2id's Argon2i pass
  for side-channel resistance.
* Bad: parameter tuning (N, r, p) is less intuitive than Argon2id's
  m/t/p; historical misconfiguration (low N) is common.

### Option C: bcrypt

* Good: battle-tested; supported everywhere.
* Bad: not memory-hard; GPU attacks are practical with modern
  hardware.
* Bad: limited to 72-byte password inputs; longer passphrases are
  silently truncated in some implementations.
* Bad: maximum work factor `cost=31` caps the hardness; cannot be
  increased beyond the algorithm's design.

### Option D: PBKDF2-SHA256 (RFC 8018)

* Good: FIPS-approved; required by some compliance frameworks.
* Bad: not memory-hard; GPU parallelism is highly effective.
* Bad: a 2023 Hashcat benchmark cracks 10^9 PBKDF2-SHA256(100k)
  hashes per second on a consumer GPU; this is not acceptable for
  a secret vault passphrase.

## Validation

* KDF parameter storage test: derive a key, store parameters + salt
  in the database, re-derive from stored parameters; assert key
  equality.
* Hardness benchmark: measure wall-clock time for a single Argon2id
  invocation at `m=65536, t=3, p=4` on reference hardware; assert
  >= 100 ms (guards against accidentally weak parameters).
* Parameter upgrade test: init with `m=32768`; at next unseal,
  upgrade to `m=65536`; assert the new wrapped key opens correctly.
* Side-channel test (informational): `cargo test --sanitizer
  memory` on the Argon2id derivation path; assert no use of
  uninitialized data.

## More Information

* RFC 9106 — Argon2 Memory-Hard Function for Password Hashing and
  Proof-of-Work Applications.
* RFC 7914 — scrypt reference.
* Password Hashing Competition results (2015):
  `https://www.password-hashing.net/`.
* `argon2` crate: `https://crates.io/crates/argon2`.
* Related: [0001-use-rust-as-implementation-language.md](0001-use-rust-as-implementation-language.md)
* Related: [0015-rust-keyring-crate-for-multi-os-keychain.md](0015-rust-keyring-crate-for-multi-os-keychain.md)

## Amendment — 2026-05-22

### Parameter Source of Truth (mandatory)

Argon2id parameters (`m_cost`, `t_cost`, `p_cost`) and the per-derivation `salt`
MUST be stored in the encrypted vault database (the `identity_and_sealing.sealed_state`
record), not in `config.toml` or any other plaintext configuration file. Reading
parameters from the database ensures that the parameters actually used to produce a
stored derived key are always consulted at unseal time, regardless of what the
current `config.toml` contains.

The `config.toml` MAY contain a `[kdf]` section expressing the operator's desired
parameters for new derivations only. At unseal time, the agent MUST read parameters
exclusively from the sealed state record, ignoring any `[kdf]` section in the
config file. Mismatches between config and stored parameters MUST be surfaced as an
informational notice, not an error.

### Minimum-Hardness Floor (mandatory)

The agent MUST enforce the following minimum-hardness floor when reading stored
Argon2id parameters at unseal time, regardless of what was stored:

| Parameter | Minimum floor |
|---|---|
| `m_cost` | 65536 KiB (64 MiB) |
| `t_cost` | 3 iterations |
| `p_cost` | 1 lane |

If any stored parameter is below its floor, the unseal MUST be rejected with a
fatal error:

```
UNSEAL_ERROR: Argon2id parameters below minimum hardness floor.
  stored m_cost=<N>, minimum=65536
  Re-init or key-rotate with compliant parameters.
```

The floor values are compile-time constants in the agent. They cannot be overridden
by `config.toml` or any runtime flag. The rationale is defence against an
attacker who compromises the database and lowers the KDF parameters to enable
offline brute-force of the passphrase; the floor prevents this downgrade attack
even if the attacker has write access to the sealed state record.

The validation test in the `Validation` section SHALL be extended to include:
attempts to unseal with `m=32768`, `m=65535`, `t=2`, and `p=0` MUST each return
`UNSEAL_ERROR`; an attempt with `m=65536, t=3, p=1` MUST succeed.

Cross-reference: [0015-rust-keyring-crate-for-multi-os-keychain.md](0015-rust-keyring-crate-for-multi-os-keychain.md).
