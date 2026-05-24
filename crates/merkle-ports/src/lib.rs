//! # merkle-ports
//!
//! Hexagonal driven-port trait surface. Adapters implement these traits.
//!
//! ## Driven ports
//!
//! | Trait | Purpose |
//! |---|---|
//! | [`Storage`] | Secret, Namespace, Audit, Policy, Backup persistence |
//! | [`Keychain`] | OS keychain abstraction for MasterKey storage |
//! | [`Crypto`] | AEAD, BLAKE3, Argon2id KDF, age encryption |
//! | [`OobNotifier`] | Out-of-band confirmation delivery |
//! | [`ExternalServices`] | SSH Bridge and HTTP Bridge |
//!
//! ## Design contract
//!
//! No concrete infrastructure types (`sqlx`, `keyring`, etc.) appear in any
//! trait signature. Domain crates depend on `merkle-ports`; they NEVER depend
//! on adapter crates.

pub mod crypto;
pub mod error;
pub mod external_services;
pub mod keychain;
pub mod oob_notifier;
pub mod storage;

pub use crypto::*;
pub use error::*;
pub use external_services::*;
pub use keychain::*;
pub use oob_notifier::*;
pub use storage::*;
