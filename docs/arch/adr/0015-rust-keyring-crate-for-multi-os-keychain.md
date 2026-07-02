---
status: accepted
date: 2026-05-22
deciders: [farchanjo]
consulted: []
informed: []
---

# 0015. Rust `keyring` Crate for Multi-OS Keychain

## Context and Problem Statement

The Master Key must be stored persistently between agent invocations
without appearing on disk in plaintext. Each target operating system
provides a native credential store: macOS Security framework
(Keychain), Linux Secret Service (GNOME Keyring / KWallet / libsecret),
and Windows Credential Manager. Accessing these stores from Rust
requires either platform-specific FFI code or a unified abstraction
crate.

Writing per-platform keychain bindings directly would add significant
maintenance surface and cross-platform testing complexity. A unified
crate that handles platform detection and provides a single API is
strongly preferred.

## Decision Drivers

* Cross-platform: a single API that works on macOS, Linux, and
  Windows without conditional compilation in the domain code.
* Pure-Rust abstraction: the crate handles platform FFI internally;
  the domain code sees only `set_password`, `get_password`, and
  `delete_password` calls.
* Well-maintained: the crate must have active maintenance and recent
  releases at decision time.
* Fallback to file-based or mock store: for CI environments without
  a keychain daemon, the crate must support a mock or file backend.
* Service identifier: the crate must support a named service
  (`dev.fapp.merkle`) and account (`master-v1`) to allow multiple
  vault installations to coexist on the same machine.
* mlock compatibility: the domain layer uses `secrecy::Secret` to
  hold the retrieved key; the `keyring` crate returns a `String`
  which must be zeroized immediately after copying into the
  `secrecy::Secret` buffer.

## Considered Options

* Option A: `keyring` crate (crates.io/crates/keyring)
* Option B: Direct platform FFI (Security.framework / libsecret /
  wincred)
* Option C: Encrypted file fallback only (no OS keychain)
* Option D: `secret-service` crate (Linux-only)

## Decision Outcome

Chosen option: "Option A: keyring crate", because it is the
standard cross-platform keychain abstraction in the Rust ecosystem,
is actively maintained, supports all three target platforms, and
provides the service + account identifier model needed to coexist
with other applications.

The Keychain Adapter in the hexagonal architecture wraps the
`keyring` crate behind a `KeychainPort` trait, allowing the mock
backend to be substituted in tests and CI:

```
KeychainPort (trait)
  ├── KeyringAdapter    (production: wraps keyring crate)
  └── MockKeychainAdapter  (test / CI: in-memory map)
```

The Service Identifier used is:
* `service = "dev.fapp.merkle"`
* `account = "master-v1"` (incremented on Master Key rotation)

Retrieved bytes are immediately copied into a `secrecy::Secret<[u8;
32]>` and the `keyring`-returned `String` is zeroized via
`zeroize::Zeroize`.

On Linux, if neither GNOME Keyring nor KWallet is running, `keyring`
falls back to a per-user encrypted file store. If no file store is
configured, the Vault Agent falls back to the Argon2id passphrase
path (see
[0005-argon2id-kdf-for-passphrase-fallback.md](0005-argon2id-kdf-for-passphrase-fallback.md)).

### Consequences

* Good, because the `KeychainPort` trait decouples the domain from
  the `keyring` crate; swapping the backend (mock in CI, real in
  production) requires no domain code change.
* Good, because the service + account naming scheme ensures that
  Merkle's entries are namespaced in the OS keychain; other
  applications' entries are not accessible.
* Good, because the `keyring` crate handles the platform-specific
  event loop requirements (e.g., macOS RunLoop for Security
  framework callbacks) internally.
* Bad, because `keyring`'s Linux backend depends on the
  `org.freedesktop.secrets` D-Bus interface, which is not available
  in all headless or containerized environments; the Argon2id
  fallback must be tested and documented for those paths.
* Bad, because the `keyring` crate returns a `String` (UTF-8) rather
  than raw bytes; the Master Key (binary 32 bytes) must be
  base64-encoded for storage and decoded on retrieval. The domain
  adapter handles this encoding transparently.

## Pros and Cons of the Options

### Option A: keyring crate

* Good: cross-platform single API; actively maintained.
* Good: service + account namespacing.
* Good: mock backend available for CI.
* Bad: Linux D-Bus dependency; base64 encoding round-trip.

### Option B: Direct platform FFI

* Good: maximum control; no intermediate crate dependency.
* Bad: three separate implementations (Security.framework,
  libsecret, wincred); significant maintenance surface.
* Bad: cross-compilation and platform testing complexity.

### Option C: Encrypted file fallback only

* Good: works everywhere; no OS dependency.
* Bad: the encrypted file is on disk; it is only as secure as the
  file's encryption key, which must itself be stored somewhere
  (circular problem).
* Bad: does not leverage OS keychain protections (hardware-backed
  keys on macOS Secure Enclave, Windows TPM, Linux TPM2).

### Option D: secret-service crate (Linux-only)

* Good: closer to the D-Bus protocol; more control on Linux.
* Bad: not cross-platform; macOS and Windows paths would still
  require separate implementations.

## Validation

* macOS integration test: store and retrieve a 32-byte key via
  `KeyringAdapter`; assert round-trip equality; verify via Keychain
  Access app that the entry exists under `dev.fapp.merkle`.
* Linux integration test: same, with GNOME Keyring running in CI.
* Mock test: use `MockKeychainAdapter` in unit tests; assert store,
  retrieve, and delete behave correctly.
* Zeroize test: retrieve a key; use `valgrind --tool=memcheck` or
  ASan to confirm the intermediate `String` buffer is zeroed.
* Fallback test: on Linux with no keychain daemon, assert agent falls
  back to Argon2id passphrase path with an appropriate log message.

## More Information

* `keyring` crate: `https://crates.io/crates/keyring`.
* `secrecy` crate: `https://crates.io/crates/secrecy`.
* `zeroize` crate: `https://crates.io/crates/zeroize`.
* macOS Security framework Keychain Services:
  `https://developer.apple.com/documentation/security/keychain_services`.
* Related: [0001-use-rust-as-implementation-language.md](0001-use-rust-as-implementation-language.md)
* Related: [0002-adopt-agent-plus-mcp-adapter-topology.md](0002-adopt-agent-plus-mcp-adapter-topology.md)
* Related: [0005-argon2id-kdf-for-passphrase-fallback.md](0005-argon2id-kdf-for-passphrase-fallback.md)

## Amendment — 2026-05-22

### OS-Specific Peer-Credential Matrix

The Companion Socket peer-credential check uses OS-specific mechanisms. The prior
text referenced `SO_PEERCRED` generically; this amendment documents the correct
per-platform mechanism:

| Platform | Mechanism | Notes |
|---|---|---|
| Linux | `SCM_CREDENTIALS` ancillary data on `AF_UNIX` | Carries `ucred` struct with `pid`, `uid`, `gid`. Sent by the peer as part of a `sendmsg(2)` call with `SOL_SOCKET` / `SCM_CREDENTIALS`. The kernel fills in the real credentials; the peer cannot forge them. |
| macOS | `LOCAL_PEERCRED` socket option (`getsockopt(sock, SOL_LOCAL, LOCAL_PEERCRED, &xucred, &len)`) | Returns `xucred` struct with the peer's effective UID and supplementary GIDs. Note: `SO_PEERCRED` is a Linux-specific name and does NOT exist on macOS; using it on macOS is a compile error. |
| Windows | `GetNamedPipeClientProcessId(pipe_handle, &pid)` followed by `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)` and `QueryFullProcessImageName` | `GetNamedPipeClientProcessId` returns the PID of the client process at the other end of the named pipe. `QueryFullProcessImageName` returns the full image path for process identity verification. |

### Linux Process Identity: `/proc/<pid>/exe`, not `/proc/<pid>/comm`

On Linux, the resolved binary path for the peer-credential check MUST be read from
`/proc/<pid>/exe` (the symlink to the canonical executable path), not from
`/proc/<pid>/comm`. The `comm` field (also available as the 2nd field of
`/proc/<pid>/stat`) is a 15-character name writable by the process itself via
`prctl(PR_SET_NAME)` and is trivially forgeable by a rogue process. `/proc/<pid>/exe`
is controlled by the kernel and cannot be written by the process; it reflects the
actual binary that was `exec`-ed.

The resolved path from `/proc/<pid>/exe` MUST be canonicalized with
`std::fs::canonicalize` before comparison against the `allowed_consumers` glob list,
to resolve any intermediate symlinks in the installation path.

### Acceptance Tests per Platform

The following acceptance tests MUST be added to the integration test suite,
one per platform, gating CI on the respective runner:

- **Linux test** (`#[cfg(target_os = "linux")]`): connect a test process to the
  companion socket; assert that `SCM_CREDENTIALS` yields the test process's real
  PID and UID; assert that the resolved `/proc/<pid>/exe` path matches the test
  binary's path.
- **macOS test** (`#[cfg(target_os = "macos")]`): same setup; assert that
  `LOCAL_PEERCRED` (NOT `SO_PEERCRED`) yields the test process's effective UID.
  Verify that passing `SO_PEERCRED` to `getsockopt` on macOS produces a compile
  error (enforced by a `#[cfg(not(target_os = "macos"))]` gate on any use of
  `SO_PEERCRED`).
- **Windows test** (`#[cfg(target_os = "windows")]`): same setup with a named
  pipe; assert that `GetNamedPipeClientProcessId` returns the correct PID and that
  `QueryFullProcessImageName` returns the test binary's full path.

Cross-reference: [0002-adopt-agent-plus-mcp-adapter-topology.md](0002-adopt-agent-plus-mcp-adapter-topology.md),
[0011-slash-only-reveal-with-oob-for-high-sensitivity.md](0011-slash-only-reveal-with-oob-for-high-sensitivity.md).

## Amendment 3 — 2026-05-23 — Unseal Error Rollback Contract

### Problem

Smoke-testing revealed that `id_guard.begin_unseal()` transitions the state
machine from `Sealed` to `Unsealing` before the Unseal Protocol is complete.
When an error occurs mid-protocol (e.g., keychain entry absent, AEAD
verification failure), the state is left in `Unsealing`. On retry, the guard
attempts the same `Sealed → Unsealing` transition and fails with "invalid state
transition from Unsealing to Unsealing", making the vault permanently
inoperable until a process restart.

### Hard Rule

**ANY error occurring during the Unseal Protocol after the state has been
transitioned to `Unsealing` MUST revert the state back to `Sealed` before
propagating the error to the caller.** No exception.

The rollback MUST occur before any `?` operator returns the error up the call
stack. A caller that receives an error code from `unseal()` MUST be able to
retry immediately without restarting the agent.

### Enumerated Failure Modes Requiring Rollback

The following error conditions each MUST trigger state rollback from
`Unsealing` to `Sealed`:

| Failure mode | Error code emitted |
|---|---|
| OS Keychain entry absent (`keychain_not_found`) | `unseal_authentication_failed` |
| OS Keychain daemon unavailable (`keychain_unavailable`) | `unseal_authentication_failed` |
| OS Keychain access denied by daemon (`keychain_access_denied`) | `unseal_authentication_failed` |
| Wrapped VRK rows absent from database (`vrk_not_found`) | `unseal_authentication_failed` |
| AEAD decryption tag verification failure (`aead_verify_failed`) | `unseal_authentication_failed` |
| Argon2id parameter mismatch (`argon2id_params_mismatch`) | `argon2id_parameters_below_minimum` |
| Argon2id KDF produces wrong key (`passphrase_invalid`) | `unseal_authentication_failed` |
| `mlock` failure when profile=paranoid (`mlock_required_failed`) | `mlock_required_failed` |
| Entropy gate failure (`entropy_unseeded`) | `entropy_unseeded` |
| Database read error during VRK fetch | `unseal_authentication_failed` |

In all cases, the Audit Entry (op=`unseal`, outcome=`error`) MUST be appended
with the appropriate `denial_reason` BEFORE the state rollback completes.
Audit emission is not skipped on the error path.

### Implementation Guidance

The preferred Rust pattern is the RAII `UnsealGuard`:

```rust
struct UnsealGuard<'a> {
    state: &'a mut VaultState,
    committed: bool,
}

impl<'a> UnsealGuard<'a> {
    fn new(state: &'a mut VaultState) -> Result<Self> {
        state.transition(VaultState::Unsealing)?;
        Ok(Self { state, committed: false })
    }
    fn commit(mut self) { self.committed = true; }
}

impl<'a> Drop for UnsealGuard<'a> {
    fn drop(&mut self) {
        if !self.committed {
            self.state.revert_to_sealed();
        }
    }
}
```

With this guard, any `?`-propagated error automatically triggers rollback via
`Drop`. The guard's `commit()` method is called only when every step has
succeeded and the VRK is fully loaded in `mlocked` memory.

Alternative: explicit `if let Err(e) = step { state.revert(); return Err(e); }`
is acceptable but more brittle; RAII is strongly preferred.

### Acceptance Tests

- `unseal()` with keychain entry absent → state is `Sealed` after the call,
  error is `unseal_authentication_failed`, retry immediately succeeds when
  keychain entry is added.
- Two consecutive `unseal()` calls both with keychain absent → both return
  `unseal_authentication_failed`; no "invalid state transition" error on the
  second call.
- `unseal()` with AEAD verify failure → state is `Sealed` after the call.
- Audit Log contains exactly one `op=unseal, outcome=error` entry per failed
  attempt, with the correct `denial_reason`.

Cross-reference: [0011-slash-only-reveal-with-oob-for-high-sensitivity.md](0011-slash-only-reveal-with-oob-for-high-sensitivity.md),
[0021-init-vault-bootstrap-ceremony.md](0021-init-vault-bootstrap-ceremony.md).

## Amendment 4 — 2026-05-23 — Persistence Verification on Write

### Problem

On macOS, the Security framework silently no-ops keychain writes when the process
lacks GUI auth or keychain access permission (e.g., background daemons, headless
CI, launchd services). The `keyring` crate returns `Ok(())` from `set_secret`,
but the entry is never persisted. The bug surfaces only at retrieve time — after
the init ceremony has reported success — causing operator confusion and an
irrecoverable vault state until the process is restarted.

### Hard Rule

**`Keychain::store()` MUST perform a `retrieve()` immediately after the write
call and compare the returned bytes against the input.** If the retrieve returns
`NotFound` or returns bytes that differ from the input, the adapter MUST propagate
`KeychainError::PersistenceFailed { service, account }` as if the write had
failed outright. The caller MUST NOT see `Ok(())` unless persistence is confirmed.

### New Error Variant

```rust
KeychainError::PersistenceFailed { service: String, account: String }
```

HTTP mapping: 503 Service Unavailable (`keychain_persistence_failed`). The
backing store is functionally broken for the current process context; the operator
must reconfigure the environment (grant keychain access, run interactively, or use
the file-backed keystore alternative).

### Rationale

The macOS Security framework requires that a process be in a GUI session or hold
a `SecKeychainUnlock` credential to perform persistent writes. Background processes
(launchd, xpc services, CI agents) do not satisfy this requirement; the write
call returns success at the C API level but is never committed to the on-disk
keychain database. A verify-after-write detects this at init time rather than at
unseal time.

### Per-Platform Behavior

| Platform | Failure scenario | Verify protects |
|---|---|---|
| macOS | Background process without GUI auth; Security framework silently no-ops the write | Yes — retrieve returns `NotFound` immediately after the write |
| Linux | DBus session absent (headless container, SSH without session bus); Secret Service daemon not running | Yes — retrieve returns `NotFound` or daemon-unavailable error |
| Windows | Credential Manager generally reliable but DPAPI envelope may fail if LSASS is impaired | Yes — retrieve returns mismatch or backend error |

### Performance Cost

Two OS keychain syscalls per `store` call. Acceptable: `store` is called only
during the init ceremony and during Master Key rotation — both are rare, operator-
initiated operations that dominate on wall-clock time, not keychain latency.

### Future Work

Introduce a `FileKeystoreAdapter` as an alternative `Keychain` trait implementation
for headless contexts where OS keychain access is unavailable by design. Registered
as a Phase 9 follow-up. NOT in scope of this amendment.

### Mock Adapter

`MockKeychainAdapter` does not need to perform the verify loop (in-memory `HashMap`
always persists). However, it MUST expose a `with_persistence_failure_for(service,
account)` builder method that causes `store` to return `PersistenceFailed` for the
specified key — allowing test suites to exercise the error path without an OS
keychain.

### Acceptance Tests

- `init` in a context where the mock is configured with a persistence failure →
  ceremony aborts with `AppError::Keychain(KeychainError::PersistenceFailed { .. })`.
- `OsKeychainAdapter::store` with a real keychain entry round-trips correctly and
  returns `Ok(())`.
- `MockKeychainAdapter::store` with `with_persistence_failure_for` injection returns
  `PersistenceFailed`.

Cross-reference: [0021-init-vault-bootstrap-ceremony.md](0021-init-vault-bootstrap-ceremony.md).

## Amendment 5 — 2026-07-02 — Persistence Probe Vindicated Against a Build-Feature Bug

A live incident (see [0029-trusted-audit-baseline-for-key-provenance-recovery.md,
Amendment 1](0029-trusted-audit-baseline-for-key-provenance-recovery.md)) initially
looked like the exact headless/no-GUI-auth failure mode Amendment 4 targets, but the
real cause was that the workspace `Cargo.toml` pinned `keyring = "3.6"` without the
`apple-native` feature, silently routing macOS to the crate's in-memory mock store.
The Amendment 4 verify-after-write check correctly caught the resulting persistence
failure and triggered the documented `file`-backend fallback exactly as designed —
the probe is vindicated, not defective. The fix was enabling `apple-native` (plus
`windows-native`), not relaxing the persistence check.
