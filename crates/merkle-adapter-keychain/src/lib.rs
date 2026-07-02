//! # merkle-adapter-keychain
//!
//! **Driven-port adapter** — cross-OS keychain via the `keyring` crate.
//!
//! ## Adapters
//!
//! | Type | Backend | Use |
//! |------|---------|-----|
//! | [`OsKeychainAdapter`] | OS native keychain | Production |
//! | [`MockKeychainAdapter`] | In-memory `HashMap` | Tests / CI |
//!
//! ## Account index sentinel
//!
//! The `keyring` crate exposes no `list` operation.  Both adapters maintain a
//! hidden sentinel entry per service:
//!
//! ```text
//! account = "<service>__merkle_account_index"
//! value   = JSON array of account names
//! ```
//!
//! `store` appends to the index (idempotent); `delete` removes from the index;
//! `list` reads and returns the decoded array.  The sentinel entry itself is
//! never returned by `list`.
//!
//! ## Platform backends
//!
//! - **macOS**: Security framework (login keychain).
//! - **Linux**: Secret Service (libsecret / GNOME Keyring) or KWallet.
//! - **Windows**: Credential Manager (`wincred`, `CRED_TYPE_GENERIC`).
//!
//! See `docs/arch/adr/0015-rust-keyring-crate-for-multi-os-keychain.md` and
//! `docs/arch/integrations/keychain-multios.md` for full design rationale.
//!
//! ## Headless / CI contexts
//!
//! [`FileKeystoreAdapter`] persists secrets to an age-encrypted file and is
//! intended for CI pipelines and Docker containers where no OS keychain
//! backend is reachable at all, or as the fallback the daemon takes when the
//! write+verify+delete persistence probe (ADR-0015 Amendment 4) catches a
//! genuine no-GUI-auth keychain failure. It is **not** the macOS default:
//! with the `apple-native` `keyring` feature enabled, the `os`/`auto`
//! backends use the real Security framework keychain from background/launchd
//! processes in the same login session. A missing `apple-native` feature
//! once routed macOS to the crate's in-memory mock store instead, which was
//! misdiagnosed as "macOS silently no-ops keychain writes" — see ADR-0015
//! Amendment 5 and ADR-0029 Amendment 1 for the corrected root cause.
//! See `docs/arch/adr/0022-file-backed-keystore-for-headless-contexts.md`.

pub mod file;
pub mod index;
pub mod migrate;
pub mod mock;
pub mod os;

pub use file::FileKeystoreAdapter;
pub use migrate::migrate_accounts;
pub use mock::MockKeychainAdapter;
pub use os::OsKeychainAdapter;
