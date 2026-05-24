//! Port-level error types.
//!
//! Each driven port defines its own error enum so that adapters can return
//! context-appropriate failures without leaking infrastructure types.

use thiserror::Error;

/// Errors returned by [`crate::Storage`] implementations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// The requested record does not exist.
    #[error("not found")]
    NotFound,
    /// A record with conflicting identity already exists.
    #[error("conflict: {0}")]
    Conflict(String),
    /// A domain constraint was violated (e.g. unique index, FK check).
    #[error("constraint violation: {0}")]
    Constraint(String),
    /// A transient storage failure that may succeed on retry.
    #[error("transient: {0}")]
    Transient(String),
    /// An opaque backend error from the underlying storage engine.
    #[error("backend: {0}")]
    Backend(#[from] BoxedError),
}

/// Errors returned by [`crate::Keychain`] implementations.
#[derive(Debug, Error)]
pub enum KeychainError {
    /// The requested keychain item does not exist.
    #[error("not found")]
    NotFound,
    /// The caller does not have permission to access the keychain item.
    #[error("permission denied")]
    PermissionDenied,
    /// A write call returned success but a subsequent retrieve confirmed the
    /// entry was not persisted (per ADR-0015 Amendment 4).
    ///
    /// Common cause: macOS Security framework in a background process without
    /// GUI auth silently no-ops keychain writes. Same protection applies on
    /// Linux when the Secret Service DBus session is absent.
    #[error("write did not persist for service={service} account={account}")]
    PersistenceFailed {
        /// The keychain service identifier.
        service: String,
        /// The keychain account identifier.
        account: String,
    },
    /// An opaque backend error from the underlying keychain provider.
    #[error("backend: {0}")]
    Backend(String),
}

/// Errors returned by [`crate::Crypto`] implementations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AEAD authentication tag verification failed; ciphertext is corrupt or tampered.
    #[error("AEAD verify failed")]
    AeadVerifyFailed,
    /// The provided key had an unexpected length.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength {
        /// The expected key length in bytes.
        expected: usize,
        /// The actual key length in bytes supplied by the caller.
        got: usize,
    },
    /// The Argon2id parameters are outside acceptable bounds.
    #[error("invalid argon2id params")]
    InvalidArgon2idParams,
    /// ECIES decryption failed; likely a wrong recipient key.
    #[error("ecies decrypt failed")]
    EciesDecryptFailed,
    /// Ed25519 signature verification failed.
    #[error("signature verify failed")]
    SignatureVerifyFailed,
    /// An error from the `age` encryption library.
    #[error("age error: {0}")]
    Age(String),
    /// An opaque backend error from the underlying crypto provider.
    #[error("backend: {0}")]
    Backend(String),
}

/// Errors returned by [`crate::OobNotifier`] implementations.
#[derive(Debug, Error)]
pub enum OobError {
    /// The OOB notifier channel is currently unavailable.
    #[error("notifier unavailable")]
    Unavailable,
    /// Dispatching the challenge to the target device failed.
    #[error("dispatch failed: {0}")]
    DispatchFailed(String),
    /// No resolution was received within the timeout window.
    #[error("timeout awaiting resolution")]
    Timeout,
    /// The Ed25519 signature on the received resolution is invalid.
    #[error("signature verify failed")]
    SignatureFailed,
    /// An opaque backend error from the underlying notifier transport.
    #[error("backend: {0}")]
    Backend(String),
}

/// Errors returned by [`crate::ExternalServices`] implementations.
#[derive(Debug, Error)]
pub enum ExternalError {
    /// Connection to the remote target could not be established.
    #[error("connect failed: {0}")]
    ConnectFailed(String),
    /// Authentication with the remote target was rejected.
    #[error("auth failed")]
    AuthFailed,
    /// The remote operation completed but returned a failure status.
    #[error("operation failed: {0}")]
    OperationFailed(String),
    /// An opaque backend error from the underlying transport.
    #[error("backend: {0}")]
    Backend(String),
}

/// A type-erased, heap-allocated error that is `Send + Sync + 'static`.
pub type BoxedError = Box<dyn std::error::Error + Send + Sync + 'static>;
