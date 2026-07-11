# Multi-OS Keychain Integration

Integration contract describing how Merkle stores and retrieves the
Master Key across macOS, Linux, and Windows using the `keyring` Rust
crate abstraction.

## 1. Overview

The Master Key (32-byte symmetric key, top of the key hierarchy) must
be persisted between vault agent restarts and protected by OS-managed
access controls. Merkle delegates this responsibility entirely to the
OS Keychain via the `keyring` crate
(<https://crates.io/crates/keyring>), which presents a uniform Rust
API over three distinct platform backends.

The **service identifier** is `dev.fapp.merkle` on every platform.
The **account** discriminator encodes the key slot and version:

| Account string | Purpose |
|---|---|
| `master-v1` | Master Key slot 1 (initial) |
| `master-v2` | Master Key slot 2 (post-rotation) |
| `recovery-pub-v1` | Recovery Public Key (age X25519 recipient, stored in plaintext but kept here for uniformity) |

Version suffixes allow atomic rotation: write the new account, verify
the read-back, then delete the old account. There is never a window
where the Master Key is absent from the keychain during rotation.

The `keyring` crate is the sole Keychain Adapter in the hexagonal
architecture. No other crate calls platform keychain APIs directly.
All reads and writes are channeled through the same adapter so that
mock injection in tests is straightforward.

## 2. Per-OS Backends

### 2.1 macOS: Security Framework

On macOS the `keyring` crate delegates to the system `Security`
framework via the `security-framework` crate. The credential is stored
in the user's default keychain (login keychain).

Key configuration:

- **Access attribute**: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
  The item is accessible after the first unlock following a boot event
  and is never synchronized to iCloud Keychain or transferred to other
  devices. This attribute satisfies both the availability requirement
  (agent auto-restarts after sleep are not blocked) and the device-
  binding requirement (backup of the keychain to another machine does
  not carry the Master Key).
- **Application label**: `dev.fapp.merkle:<account>` to prevent
  collisions with other applications using the same service identifier.
- **Touch ID integration**: see Section 4.

On macOS the `keyring` crate performs `SecItemCopyMatching` (read),
`SecItemAdd` or `SecItemUpdate` (write), and `SecItemDelete` (delete).
The agent process must be in the same user session as the keychain;
running under `launchd` in a user agent context satisfies this.

Error mapping from Security framework OSStatus codes:

| OSStatus | Merkle error | Action |
|---|---|---|
| `errSecItemNotFound` (-25300) | `KeychainEntryMissing` | Trigger passphrase fallback or recovery |
| `errSecAuthFailed` (-25293) | `KeychainAuthFailed` | Prompt for Touch ID or keychain unlock |
| `errSecInteractionNotAllowed` (-25308) | `KeychainLocked` | Vault remains Sealed; notify operator |
| Any other | `KeychainUnknownError` | Log OSStatus, surface to operator |

### 2.2 Linux: Secret Service and KWallet

On Linux the `keyring` crate prefers **libsecret** (Secret Service
protocol over D-Bus) and falls back to **KWallet** when libsecret is
unavailable.

#### Secret Service (libsecret)

The Secret Service protocol (freedesktop.org) is implemented by GNOME
Keyring (`gnome-keyring-daemon`) and KDE's `kwallet5` compatibility
layer. The crate opens a D-Bus session connection and stores items in
the default collection (typically `login` or `default`).

Session types negotiated by the crate: `dh-ietf1024-sha256-aes128-cbc-pkcs7`
(encrypted transport) preferred; `plain` only when the daemon does not
offer ECDH. The agent must be running in a user session with a live
D-Bus session bus (set by `DBUS_SESSION_BUS_ADDRESS` or auto-discovered
via `XDG_RUNTIME_DIR`).

Headless environments (see Section 3) do not expose a Secret Service
daemon; `keyring` returns `NoStorageAccess` which triggers the
passphrase fallback.

#### KWallet Fallback

When Secret Service is not available `keyring` attempts the KWallet
D-Bus interface (`org.kde.KWallet`). The wallet name defaults to
`kdewallet`. Items are stored in the `Passwords` folder under the
service identifier.

KWallet may present a password prompt on first access if the wallet
is closed. In a headless or CI context this will time out and fall
through to the passphrase fallback.

#### Error mapping

| Scenario | Merkle error | Action |
|---|---|---|
| D-Bus connection refused | `KeychainUnavailable` | Passphrase fallback |
| Collection locked, no unlock | `KeychainLocked` | Vault stays Sealed |
| Item not found | `KeychainEntryMissing` | Recovery flow |

### 2.3 Windows: Credential Manager

On Windows the `keyring` crate uses the `wincred` API
(`CredWrite`, `CredRead`, `CredDelete` from `advapi32.dll`). Credentials
are stored as `CRED_TYPE_GENERIC` items under the target name
keychain service dev.fapp.merkle with account name.

The `CredentialBlob` field holds the raw 32-byte Master Key. Size is
within the 512-byte limit for generic credentials. The
`CRED_PERSIST_LOCAL_MACHINE` persist flag is used so the credential
survives user logoff but is not roamed to other machines.

Windows Credential Manager credentials are protected by the DPAPI
(`CryptProtectData`) implicitly by the OS. The agent process must run
under the same user account as the credential store. Running as a
different elevated user (e.g., SYSTEM) cannot access user-scope
credentials; the agent must run in the user's context.

Error mapping:

| Win32 error | Merkle error | Action |
|---|---|---|
| `ERROR_NOT_FOUND` (1168) | `KeychainEntryMissing` | Recovery flow |
| `ERROR_LOGON_FAILURE` (1326) | `KeychainAuthFailed` | DPAPI decryption failed |
| `ERROR_NO_SUCH_LOGON_SESSION` (1312) | `KeychainUnavailable` | Passphrase fallback |

## 3. Fallback Behavior: Passphrase-Derived Master Key

When no OS keychain backend is reachable (headless Linux server without
a running Secret Service daemon, CI/CD environment, or Docker container)
the Vault Agent falls back to deriving the Master Key from an operator-
supplied passphrase using Argon2id (RFC 9106).

### Algorithm Parameters

| Parameter | Default | Override via |
|---|---|---|
| Memory (`m`) | 65536 KiB (64 MiB) | `config.toml` `[kdf] memory_kib` |
| Iterations (`t`) | 3 | `config.toml` `[kdf] iterations` |
| Parallelism (`p`) | 4 | `config.toml` `[kdf] parallelism` |
| Output length | 32 bytes | Fixed |
| Salt | 16-byte random, stored in `config.toml` | Generated at `merkle init` |
| Version | Argon2id | Fixed |

The salt is generated once at `merkle init` and stored in plaintext in
`config.toml` under `[kdf] salt_hex`. This is safe because the salt's
purpose is to prevent precomputation attacks across installations, not
to be secret.

The derived key is equivalent to the Master Key and is used to unwrap
the Vault Root Key from the database, exactly as the keychain-stored
Master Key would be. The agent holds the derived key in mlocked memory
and discards the passphrase immediately after derivation.

**Warning**: In the fallback path the security boundary degrades from
OS-managed keychain protection to passphrase strength. Operators
should use the keychain path in production.

## 4. Touch ID and Biometric Integration

Touch ID integration is macOS-specific and opt-in. It augments the
standard keychain access with a biometric re-authentication gate.

Configuration:

```toml
[keychain]
touch_id_required = true
```

When `touch_id_required = true`:

1. On each unseal attempt the agent evaluates an `LAContext` with
   policy `LAPolicyDeviceOwnerAuthenticationWithBiometrics`.
2. `LAContext.evaluatePolicy(_:localizedReason:reply:)` is called with
   the reason string `"Merkle vault unseal"`.
3. On success the `LAContext` is passed to `SecItemCopyMatching` via
   the `kSecUseAuthenticationContext` attribute, authorizing the
   keychain read.
4. On failure (Touch ID not enrolled, finger rejected, or policy
   locked) the agent returns `KeychainAuthFailed` and the vault
   remains Sealed.

The `LAContext` evaluation runs on the main thread of the agent
process. The agent must not be a background-only daemon without a
runloop; `launchd` user agents with `RunAtLoad = true` satisfy this
requirement.

`touch_id_required = false` (default) means the keychain item is
accessible by any process running as the owning user after first
unlock; Touch ID is not involved.

Interaction with biometric changes: if the user re-enrolls their
fingerprint after `merkle init`, the `kSecAttrAccessControl` ACL may
invalidate existing keychain items depending on the macOS version.
Merkle detects `errSecItemNotFound` after a re-enrollment and instructs
the operator to run `merkle unseal --passphrase` to re-import the
Master Key from a backup or recovery path.

## 5. Threats and Mitigations

| Threat | Mitigation |
|---|---|
| Keychain compromise (attacker reads Master Key) | Master Key alone is insufficient: the Vault Root Key is wrapped twice — once by the Master Key and once for the Recovery Public Key. An attacker with only the Master Key can read current Secrets but cannot impersonate the Recovery Key holder. Rotation of the Master Key (`merkle rekey`) revokes the compromised key. |
| Local malware extracting keychain entries | macOS: ACL on keychain item restricts access to the `merkle` process code signature; other processes receive `errSecInteractionNotAllowed`. Linux: Secret Service collection is session-scoped; malware in the same user session can read it — mitigation is full disk encryption + OS-level mandatory access control. Windows: DPAPI binding to the user account makes extraction from another user account infeasible. |
| Passphrase brute force (fallback path) | Argon2id parameters (m=64 MiB, t=3, p=4) make offline attacks expensive. Operators should use a long random passphrase and store it in a separate password manager. |
| Key material in core dumps | Agent marks the Master Key and Vault Root Key regions with `mlock` / `madvise(MADV_DONTDUMP)` on Linux and the equivalent on macOS and Windows to suppress core dump inclusion. |
| Keychain backup to iCloud | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` explicitly prevents iCloud sync. Verified by the `vault.doctor` diagnostic. |

## 6. Lifecycle

### 6.1 Fetch on Unseal

On each Unseal Protocol invocation the agent performs exactly one
keychain read:

```
keyring::Entry::new("dev.fapp.merkle", "master-v1")?.get_password()
```

The returned byte string is the 32-byte Master Key (hex or base64
encoded by the crate as required by the backend). The key is decoded,
mlocked, used to decrypt the Vault Root Key from the database, and the
Vault Root Key is mlocked in its own allocation. The Master Key byte
vector is zeroed and dropped immediately after Vault Root Key
decryption.

### 6.2 Never Persisted Outside Keychain

The Master Key is only ever held in:

1. The OS Keychain (the backend's encrypted store).
2. Process memory during the Unseal Protocol window (mlocked, zeroed on
   drop).

It is never written to `config.toml`, the SQLite database, a log file,
or the MCP transport.

### 6.3 Rotation

Master Key rotation (`merkle rekey`) follows this sequence:

1. Generate a new 32-byte Master Key at random.
2. Write it to `keyring::Entry::new("dev.fapp.merkle", "master-v2")`.
3. Read it back and verify the round-trip.
4. Re-wrap the Vault Root Key under the new Master Key.
5. Update the database with the new wrapped Vault Root Key blob.
6. Commit the database transaction.
7. Delete `keyring::Entry::new("dev.fapp.merkle", "master-v1")`.
8. Update `config.toml` `active_master_slot = "master-v2"`.

If any step from 1 to 6 fails, the old Master Key and wrapped Vault
Root Key remain in effect and the new entry is deleted. The rotation
is atomic with respect to the database; it is not atomic with respect
to the keychain, but the old entry is never deleted before the database
commit succeeds.

## 7. References

- `keyring` crate: <https://crates.io/crates/keyring>
- [ADR-0015: Rust keyring crate for multi-OS keychain](../adr/0015-rust-keyring-crate-for-multi-os-keychain.md)
- RFC 9106: Argon2 Memory-Hard Function
- macOS Security framework: <https://developer.apple.com/documentation/security>
- freedesktop.org Secret Service specification: <https://specifications.freedesktop.org/secret-service/>
- Windows Credential Manager: <https://learn.microsoft.com/en-us/windows/win32/secauthn/credentials-management>
- Glossary: `../glossary.md` (Master Key, Recovery Key, Unseal Protocol, Service Identifier)
