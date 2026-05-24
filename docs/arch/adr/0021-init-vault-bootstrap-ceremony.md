---
status: accepted
date: 2026-05-23
deciders: [farchanjo]
consulted: [Architecture, Security]
informed: [Engineering, SRE]
---

# 0021. Init Vault Bootstrap Ceremony

## Context and Problem Statement

The Merkle CLI supports `merkle init` and `merkle init --non-interactive` to
bootstrap a fresh vault. Smoke-testing revealed that the command prints "ok"
without calling any agent endpoint, because no `POST /v1/agent/init` endpoint
exists in the OpenAPI spec, no `InitVaultCommand` is defined in the application
layer, and no Gherkin acceptance scenarios cover the bootstrap path.

As a consequence, a freshly installed vault has no Master Key in the OS
Keychain and no Vault Root Key in the database. Every subsequent `merkle unseal`
fails with "Keychain not found" because the initialization ceremony that would
generate and persist those keys was never specified and therefore never
implemented.

The bootstrap ceremony is the highest-privilege operation in the key hierarchy:
it generates the Master Key, derives the Vault Root Key, dual-wraps it, and
displays the Recovery Key exactly once. Correct specification of the ceremony is
a prerequisite for safe implementation.

## Decision Drivers

* **Functional completeness**: `merkle init` is the entry point for every new
  installation; without a machine-checkable spec the implementation is
  unconstrained.
* **Key hierarchy integrity**: the ceremony must produce the dual-wrapped Vault
  Root Key (ADR-0003) and the age Recovery Key (ADR-0006) atomically; a partial
  completion leaves the vault in an unrecoverable state.
* **Idempotency and safety**: if init is called on an already-initialized vault
  it must refuse, not silently overwrite the Master Key.
* **Operator UX**: the Recovery Key is sensitive and must be shown exactly once;
  non-interactive mode must not suppress it silently.
* **Audit coverage**: the init event must appear in the Audit Log with the same
  rigor as any other vault mutation.
* **Spec-first**: per ADR-0018, the endpoint contract, CUE schema, and Gherkin
  scenarios must be authored before the Rust implementation begins.

## Considered Options

* Option A: Spec init as a single atomic HTTP endpoint on the Companion Socket
  (`POST /v1/agent/init`), peer-credential-authenticated, with all ceremony
  steps executed inside the agent.
* Option B: Init as a CLI-only operation that never calls the agent; the CLI
  generates keys and writes them directly to keychain and database.
* Option C: Init as a multi-step wizard where each step is a separate endpoint
  call.

## Decision Outcome

Chosen option: "Option A: single atomic HTTP endpoint", because it preserves
the hexagonal architecture (agent owns all key operations), is consistent with
the existing Companion Socket transport, and allows peer-credential
authentication at the Unix socket level. Options B and C introduce either a
split-authority problem (CLI writing keys the agent does not own) or partial-
completion windows that are harder to make atomic.

### Ceremony Steps

The agent MUST execute the following steps in order, atomically:

1. **Check idempotency.** Read the OS Keychain entry for service
   `dev.fapp.merkle`, account `master-v1`. If found, return `409 Conflict`
   with problem type `already_initialized`. Do NOT proceed.

2. **Generate Master Key.** Generate 32 cryptographically-random bytes via
   `OsRng` (Rust `rand::rngs::OsRng`). This is the Master Key (generation 1).

3. **Persist Master Key.** Store the Master Key in the OS Keychain under
   service `dev.fapp.merkle`, account `master-v1`, base64-encoded per
   ADR-0015. If keychain write fails, abort and return `503` — do not proceed.

4. **Generate Recovery Key.** Generate an `age` X25519 identity (secret key +
   public key) via `OsRng`. The secret key is NOT stored by the agent; only the
   Recovery Public Key (the `age` recipient string) is retained.

5. **Generate Vault Root Key.** Generate 32 cryptographically-random bytes via
   `OsRng`. This is the Vault Root Key (version 1).

6. **Dual-wrap Vault Root Key.** Produce two wrapped copies:
   - `wrapped_by = "master"`: encrypt the Vault Root Key with the Master Key
     using XChaCha20-Poly1305 (ADR-0004), with a fresh random 24-byte nonce.
   - `wrapped_by = "recovery"`: encrypt the Vault Root Key for the Recovery
     Public Key using `age` encryption (ADR-0006).

7. **Persist wrapped Vault Root Key.** Write both wrapped copies atomically
   to the `vault_root_key` table in SQLite within a single transaction (ADR-0003).
   If the transaction fails, delete the keychain entry added in step 3 and
   return `500`.

8. **Emit audit entry.** Append an Audit Entry with `op = "init"`,
   `outcome = "allow"`, `namespace_id = vault_root_namespace_id`. The entry
   must be appended before responding to the caller.

9. **Return response.** Return `201 Created` with:
   - `vault_id`: UUIDv7 identifying this installation.
   - `recovery_key`: the `age` X25519 recipient string (public key). This is
     the ONLY time the Recovery Key representation is transmitted.
   - `master_key_keychain_ref`: canonical service + account string
     (`dev.fapp.merkle/master-v1`).

### Recovery Key Display Contract

The Recovery Key MUST be printed to the CLI stdout before any other output,
regardless of `--non-interactive`. The non-interactive flag suppresses the
interactive confirmation prompt (press Enter to confirm you have saved the
key) but does NOT suppress the key display. An operator who cannot save the
key before the process exits has accepted the loss risk.

### Idempotency

If `POST /v1/agent/init` is called on an already-initialized vault:

- The agent MUST return `409 Conflict` with problem type `already_initialized`.
- The agent MUST NOT generate new keys, overwrite the existing Master Key in
  the keychain, or alter any database rows.
- The agent MUST NOT emit an Audit Entry for the refused call.

### Authentication

Peer-credential authentication at the Unix socket level applies, consistent
with all other Companion Socket endpoints. The caller UID must match the agent
UID. No additional operator confirmation (slash command or OOB) is required for
init, because the agent is not yet initialized and therefore has no Namespace
Policy to consult.

### Security Profile at Init

The caller MAY supply a `security_profile` in the request body (`low`,
`balanced`, or `paranoid`). When absent, the agent defaults to `balanced`.
The security profile is stored in `config.toml` and governs subsequent
Namespace Policy defaults. It is not modifiable after init without explicit
key rotation and policy migration.

### Consequences

* Good, because the agent is the sole authority over key generation; the CLI
  remains a thin adapter that formats and forwards.
* Good, because the atomic implementation of all eight ceremony steps inside a
  single agent transaction eliminates partial-completion windows.
* Good, because Gherkin scenarios (see `docs/arch/specs/features/init_vault.feature`)
  provide executable acceptance criteria before implementation begins.
* Bad, because the `409 already_initialized` check is the agent's first keychain
  read on init; a transient keychain error could produce a false positive.
  Implementation MUST distinguish "entry exists" from "keychain unavailable":
  the former returns `409`, the latter returns `503`.
* Bad, because the `age` Recovery Key display on stdout couples the agent's
  HTTP response to the CLI TTY formatting; the CLI must not truncate or
  reformat the key string.
* Neutral, because init is a one-time operation; its latency (Argon2id is not
  involved) is dominated by OS Keychain write time.

## Pros and Cons of the Options

### Option A: Single atomic endpoint (chosen)

* Good: agent owns all key operations; consistent with hexagonal architecture.
* Good: peer-credential authentication at socket level; no additional auth layer.
* Good: single transaction makes partial-completion impossible at the DB level.
* Bad: keychain write in step 3 is outside the DB transaction; compensating
  delete on DB failure adds implementation complexity.

### Option B: CLI-only operation (no agent call)

* Good: no inter-process communication; simpler implementation.
* Bad: CLI must own key generation, violating the hexagonal boundary.
* Bad: the agent cannot audit the init event because it was not involved.
* Bad: database and keychain writes from two different processes risks
  race conditions if another process calls `unseal` concurrently.

### Option C: Multi-step wizard (separate endpoints)

* Good: each step is independently testable.
* Bad: partial completion is the default; every interrupted init leaves the
  vault in an inconsistent state that requires manual cleanup.
* Bad: complexity of a saga or compensating transactions across HTTP calls.

## Validation

- `POST /v1/agent/init` on a fresh vault → 201 with `recovery_key` and
  `master_key_keychain_ref`.
- OS Keychain contains entry `dev.fapp.merkle/master-v1` after successful init.
- SQLite `vault_root_key` table contains exactly two rows with `version=1`:
  one `wrapped_by="master"`, one `wrapped_by="recovery"`.
- Audit Log contains one entry with `op=init`, `outcome=allow`.
- Calling `POST /v1/agent/init` a second time → 409 `already_initialized`.
- `--non-interactive` flag: Recovery Key appears on stdout; no confirmation
  prompt is shown.
- Subsequent `POST /v1/agent/unseal` succeeds after init.

## More Information

* [0003-sqlite-with-per-blob-encryption.md](0003-sqlite-with-per-blob-encryption.md) — storage backend for wrapped VRK.
* [0005-argon2id-kdf-for-passphrase-fallback.md](0005-argon2id-kdf-for-passphrase-fallback.md) — KDF used in unseal; not in init (no passphrase at init time).
* [0006-age-encryption-for-backups-and-recovery.md](0006-age-encryption-for-backups-and-recovery.md) — age format for Recovery Key wrapping.
* [0015-rust-keyring-crate-for-multi-os-keychain.md](0015-rust-keyring-crate-for-multi-os-keychain.md) — keychain adapter for Master Key storage.
* [0018-full-coverage-validation-as-architectural-contract.md](0018-full-coverage-validation-as-architectural-contract.md) — spec-first mandate.
* Endpoint schema: `docs/arch/integrations/openapi/companion-socket.yaml`
  `POST /v1/agent/init`.
* CUE schemas: `docs/arch/schemas/identity_and_sealing/init_vault.cue`.
* Feature: `docs/arch/specs/features/init_vault.feature`.
