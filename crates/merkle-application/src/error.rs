//! `AppError` — unified error type for the application layer.
//!
//! Unifies domain and port errors so that driving adapters (MCP, CLI,
//! Companion Socket) only need to match against a single type.

use thiserror::Error;

/// Unified error type for every command and query handler.
#[derive(Debug, Error)]
pub enum AppError {
    /// Operation rejected because the vault is currently sealed.
    #[error("vault sealed")]
    VaultSealed,

    /// A policy evaluator denied the operation.
    #[error("policy denied: {0}")]
    PolicyDenied(String),

    /// The requested resource was not found.
    #[error("not found")]
    NotFound,

    /// The supplied input did not pass validation.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// A storage port error.
    #[error("storage: {0}")]
    Storage(#[from] merkle_ports::StorageError),

    /// A cryptographic port error.
    #[error("crypto: {0}")]
    Crypto(#[from] merkle_ports::CryptoError),

    /// A keychain port error.
    #[error("keychain: {0}")]
    Keychain(#[from] merkle_ports::KeychainError),

    /// An OOB notifier port error.
    #[error("oob: {0}")]
    Oob(#[from] merkle_ports::OobError),

    /// An external services port error.
    #[error("external: {0}")]
    External(#[from] merkle_ports::ExternalError),

    /// A domain-layer error (converted to a string to avoid re-exporting every
    /// domain error enum).
    #[error("domain: {0}")]
    Domain(String),

    /// Functionality that has not yet been implemented.
    #[error("not implemented")]
    NotImplemented,

    /// Backup ciphertext failed HMAC verification (encrypt-then-MAC).
    #[error("backup_integrity_check_failed")]
    BackupIntegrity,

    /// The restore plan TTL elapsed before apply.
    #[error("restore plan expired")]
    RestorePlanExpired,

    /// The restore plan was already applied.
    #[error("restore plan already applied")]
    RestorePlanAlreadyApplied,
}
