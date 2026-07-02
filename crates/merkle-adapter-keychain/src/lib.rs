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
//! intended for CI pipelines, Docker containers, and macOS background processes
//! where the OS keychain is unavailable or silently no-ops writes.
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
