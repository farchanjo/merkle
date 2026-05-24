//! [`Keychain`] driven port — OS keychain abstraction.
//!
//! Used by the Identity and Sealing context to store and retrieve the
//! [`MasterKey`](merkle_domain_identity::MasterKey) without exposing plaintext
//! bytes to the file system. Adapters implement this trait over the platform
//! keychain (macOS Keychain, Linux Secret Service, Windows Credential Store).

use async_trait::async_trait;
use crate::error::KeychainError;

/// Driven port for operating-system keychain operations.
///
/// Implementations MUST zeroize key material from memory as soon as it is
/// no longer needed.
#[async_trait]
pub trait Keychain: Send + Sync {
    /// Store `secret` bytes under the `(service, account)` key tuple.
    ///
    /// Overwrites any pre-existing entry with the same key tuple.
    async fn store(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), KeychainError>;

    /// Retrieve the secret bytes stored under `(service, account)`.
    ///
    /// Returns [`KeychainError::NotFound`] if no entry exists.
    async fn retrieve(&self, service: &str, account: &str) -> Result<Vec<u8>, KeychainError>;

    /// Delete the keychain entry at `(service, account)`.
    ///
    /// Returns [`KeychainError::NotFound`] if no entry exists.
    async fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError>;

    /// List all account names stored under `service`.
    async fn list(&self, service: &str) -> Result<Vec<String>, KeychainError>;
}
