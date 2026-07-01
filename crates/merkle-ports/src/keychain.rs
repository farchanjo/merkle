//! [`Keychain`] driven port — OS keychain abstraction.
//!
//! Used by the Identity and Sealing context to store and retrieve the
//! [`MasterKey`](merkle_domain_identity::MasterKey) without exposing plaintext
//! bytes to the file system. Adapters implement this trait over the platform
//! keychain (macOS Keychain, Linux Secret Service, Windows Credential Store).

use crate::error::KeychainError;
use async_trait::async_trait;

/// Driven port for operating-system keychain operations.
///
/// Implementations MUST zeroize key material from memory as soon as it is
/// no longer needed.
#[async_trait]
pub trait Keychain: Send + Sync {
    /// Store `secret` bytes under the `(service, account)` key tuple.
    ///
    /// Overwrites any pre-existing entry with the same key tuple.
    async fn store(&self, service: &str, account: &str, secret: &[u8])
    -> Result<(), KeychainError>;

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

    /// Human-readable name of the concrete backend (`"os"`, `"file"`, `"mock"`).
    ///
    /// Surfaced by diagnostics (`doctor`) so the operator can see which backend
    /// actually resolved — the `auto` policy silently falls back from the OS
    /// keychain to the file keystore under a headless/unapproved process
    /// (ADR-0015), and that resolved choice determines VRK provenance. Defaults
    /// to `"unknown"`; each adapter overrides it.
    fn backend_name(&self) -> &'static str {
        "unknown"
    }
}
