---
status: accepted
date: 2026-05-23
deciders: [farchanjo]
consulted: [Security, Architecture]
informed: [Engineering, SRE]
---

# 0022. File-Backed Keystore for Headless Contexts

## Context and Problem Statement

OS keychains require GUI-session auth in several deployment scenarios:

- **macOS background process** — the Security framework silently no-ops keychain
  writes when no GUI session is active (first observed in ADR-0015 Amendment 4).
- **Headless Linux** — the Secret Service (libsecret / GNOME Keyring) requires a
  live DBus user session; container images and bare-metal CI hosts typically have
  none.
- **Windows non-interactive service** — Credential Manager is inaccessible from
  services that run under `SYSTEM` or `LocalService` with no window station.

ADR-0015 Amendment 4 made these failures loud (the `PersistenceFailed` variant),
but provided no alternative path. Operators running Merkle in CI pipelines,
Docker-based integration tests, or macOS background launch-agent contexts are
blocked from using any keychain-backed feature.

The decision must satisfy:
- Secrets must never be stored in plaintext on disk.
- Passphrase authentication must meet the Argon2id floor from ADR-0005.
- The existing `Keychain` port trait must be respected; no domain changes.
- The operator must be able to select the backing implementation explicitly or
  let the agent fall back automatically.

## Decision Drivers

- Headless usability: CI pipelines and daemon contexts must function.
- Reproducibility: integration tests must work without a real OS keychain.
- Security: file-at-rest must be encrypted with forward-secret key derivation.
- Ergonomics: zero changes to domain crates or the `Keychain` port surface.
- Recovery target: aligns with ADR-0006 backup/recovery story (encrypted blob
  is a natural off-site backup target for Recovery-Key holders).

## Considered Options

### Option A — OS keychain only (status quo)

Keep `OsKeychainAdapter` as the sole implementation. Headless contexts fail with
`PersistenceFailed` and the agent cannot start.

**Pros:** simplest; relies on platform HW-backed secret storage.
**Cons:** blocks CI, Docker, macOS background processes. Operators have no
recourse.

**Decision: rejected.** The failures are real and frequent; no alternative path
is untenable.

### Option B — File keystore always (replace OS keychain)

Replace `OsKeychainAdapter` with `FileKeystoreAdapter` as the default in all
contexts.

**Pros:** uniform behaviour across platforms; easy to test.
**Cons:** loses OS keychain HW-backing (Secure Enclave on Apple Silicon, TPM on
Windows); weakens the security posture for interactive desktop use.

**Decision: rejected.** The OS keychain HW-backing is a meaningful security
property that should not be sacrificed for all deployments.

### Option C — Selectable backend with auto-fallback (chosen)

Introduce a `[keystore]` config section with `backend = "os" | "file" | "auto"`.
The new `FileKeystoreAdapter` implements the same `Keychain` port trait as
`OsKeychainAdapter`. Selection logic:

| `backend` value | Behaviour |
|---|---|
| `"os"` | Use `OsKeychainAdapter` exclusively; fail loud if OS keychain fails. |
| `"file"` | Use `FileKeystoreAdapter` exclusively; never try OS keychain. |
| `"auto"` (default) | Try `OsKeychainAdapter` first; on `PersistenceFailed`, switch to `FileKeystoreAdapter` transparently. |

**Pros:** interactive users keep HW-backed OS keychain; CI / headless ops use
the file backend; migration path is zero-config for most operators.
**Cons:** operator must safeguard the passphrase (`MERKLE_KEYSTORE_PASSPHRASE`);
single encrypted file is a backup target.

**Decision: accepted.**

## Decision Outcome

Chosen option: "Option: FileKeystoreAdapter for headless/auto fallback"

Introduce **`FileKeystoreAdapter`** as a new implementation of
`merkle_ports::Keychain` in `crates/merkle-adapter-keychain`.

### Storage format

```
~/.local/share/merkle/keystore.age   (overridden by $MERKLE_KEYSTORE_PATH)
```

The file is an `age` ciphertext whose plaintext is a JSON object:

```json
{
  "dev.fapp.merkle": {
    "master-v1": "<base64-encoded-secret>",
    "dev.fapp.merkle__merkle_account_index": "<base64-encoded-index>"
  }
}
```

Outer key: `service`; inner key: `account`; value: standard base64 of the raw
secret bytes.

### Encryption

`age` passphrase-based encryption using a passphrase derived from the operator-
supplied string. The `age` crate internally applies `scrypt` when using the
`age::Encryptor::with_user_passphrase` API, which satisfies the forward-secrecy
requirement. The passphrase is sourced (in priority order):

1. `MERKLE_KEYSTORE_PASSPHRASE` environment variable.
2. TTY prompt via `rpassword` (interactive fallback, consistent with F7.B
   unseal fix).

### Concurrency

- In-process: a `tokio::sync::Mutex<HashMap<(String, String), Vec<u8>>>` guards
  the in-memory snapshot. All operations lock the mutex, mutate the snapshot,
  then call `persist`.
- Cross-process: `flock(2)` advisory lock on the keystore file before each
  write. Best-effort; failure to acquire the lock returns
  `KeychainError::Backend`.

### Atomic writes

Each `persist` call writes to a sibling `keystore.age.tmp` file (same directory
for atomic rename semantics), then renames it over the canonical path. This
prevents corrupt-on-crash scenarios.

### Corruption handling

If `age` decryption fails on `open`, `FileKeystoreAdapter::open` returns
`KeychainError::Backend` with a descriptive message. The agent fails loud; it
never silently overwrites a corrupt file.

### Config wiring

```toml
[keystore]
backend = "auto"            # "os" | "file" | "auto"
# file_path = "~/.local/share/merkle/keystore.age"   # optional override
```

In `build_app_context` (`run.rs`):

- `backend = "os"` → `Arc<OsKeychainAdapter>` (existing path, no change).
- `backend = "file"` → `Arc<FileKeystoreAdapter>` opened from config path.
- `backend = "auto"` → attempt `OsKeychainAdapter`; on `PersistenceFailed` probe
  during a test-store, switch to `FileKeystoreAdapter`.

### Consequences

#### Positive

- Headless CI and Docker-based integration tests are unblocked.
- macOS launch-agent operators have a working alternative without GUI auth.
- The encrypted file is a natural backup artefact (aligns with ADR-0006).
- Zero changes to domain crates or the `Keychain` port surface.

#### Negative

- Operator must remember the passphrase. Loss of passphrase = loss of keystore.
  Operators should store the passphrase in a secrets manager.
- The single-file blob is now a recovery-key-protected backup target; operators
  must include it in their backup rotation (ADR-0006 scope extension).
- File backend has no hardware-backed key storage; the security posture is lower
  than OS keychain on platforms with Secure Enclave / TPM.

#### Neutral

- `MERKLE_KEYSTORE_PASSPHRASE` env var introduces a new operator secret that CI
  pipelines must provision (GitHub Actions: `secrets.MERKLE_KEYSTORE_PASSPHRASE`).
- The `age` crate is already a workspace dependency (used in backup/recovery).
  No new supply-chain surface.
