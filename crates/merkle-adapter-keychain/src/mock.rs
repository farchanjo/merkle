//! In-memory mock keychain adapter for tests and CI.
//!
//! `MockKeychainAdapter` implements [`merkle_ports::Keychain`] using a
//! `parking_lot::Mutex`-guarded `HashMap` so it can be shared across async
//! tasks without requiring `Arc<tokio::sync::Mutex<…>>`.  The adapter
//! maintains the same account-index sentinel as `OsKeychainAdapter` so test
//! coverage applies to both implementations uniformly.

use std::collections::HashMap;

use async_trait::async_trait;
use merkle_ports::{Keychain, KeychainError};
use parking_lot::Mutex;
use tracing::debug;

use crate::index::{
    decode_index, encode_index, index_add, index_remove, sentinel_account, INDEX_SUFFIX,
};

/// Key type for the internal store: `(service, account)`.
type StoreKey = (String, String);

/// Error injection key: `(service, account)` → injected error kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectedError {
    /// Simulate the entry not being found.
    NotFound,
    /// Simulate the keychain backend being unavailable.
    Unavailable,
    /// Simulate a silent persistence failure (per ADR-0015 Amendment 4):
    /// the write call succeeds but the entry is not actually persisted.
    /// The adapter returns `KeychainError::PersistenceFailed` from `store`.
    PersistenceFailed,
}

/// In-memory keychain adapter.
///
/// Thread-safe via `parking_lot::Mutex`; the guard is never held across an
/// `.await` point because all mutations happen synchronously inside the lock
/// before returning.
#[derive(Debug, Default)]
pub struct MockKeychainAdapter {
    store: Mutex<HashMap<StoreKey, Vec<u8>>>,
    /// Error injections: any retrieve/store/delete for the specified key will
    /// return the corresponding [`KeychainError`] rather than hitting the store.
    injected_errors: Mutex<HashMap<StoreKey, InjectedError>>,
    /// When `true`, all store (write) operations return `Unavailable`.
    write_unavailable: Mutex<bool>,
    /// Keys configured to return `PersistenceFailed` from `store` (per
    /// ADR-0015 Amendment 4). In-memory HashMap always persists in practice;
    /// this field exists solely to let tests exercise the error path.
    persistence_failures: Mutex<std::collections::HashSet<StoreKey>>,
}

impl MockKeychainAdapter {
    /// Create a new, empty mock adapter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject an error for a specific `(service, account)` key.
    ///
    /// After calling this, any retrieve/delete call for that key returns the
    /// injected error instead of the stored value.
    pub fn inject_error(&self, service: &str, account: &str, error: InjectedError) {
        self.injected_errors
            .lock()
            .insert((service.to_owned(), account.to_owned()), error);
    }

    /// Make all write (store) operations fail with `Unavailable`.
    pub fn set_write_unavailable(&self, unavailable: bool) {
        *self.write_unavailable.lock() = unavailable;
    }

    /// Clear all injected errors.
    pub fn clear_injected_errors(&self) {
        self.injected_errors.lock().clear();
    }

    /// Configure `store(service, account, _)` to return
    /// `KeychainError::PersistenceFailed` for the specified key.
    ///
    /// Use this in tests that need to exercise the ADR-0015 Amendment 4 error
    /// path without requiring an OS keychain that silently drops writes.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use merkle_adapter_keychain::MockKeychainAdapter;
    /// # use merkle_ports::KeychainError;
    /// # use merkle_ports::Keychain;
    /// # #[tokio::main] async fn main() {
    /// let mock = MockKeychainAdapter::new();
    /// mock.with_persistence_failure_for("svc", "acct");
    /// let result = mock.store("svc", "acct", &[1u8; 32]).await;
    /// assert!(matches!(result, Err(KeychainError::PersistenceFailed { .. })));
    /// # }
    /// ```
    pub fn with_persistence_failure_for(&self, service: &str, account: &str) {
        self.persistence_failures
            .lock()
            .insert((service.to_owned(), account.to_owned()));
    }

    /// Remove a previously configured persistence failure for `(service, account)`.
    pub fn clear_persistence_failure_for(&self, service: &str, account: &str) {
        self.persistence_failures
            .lock()
            .remove(&(service.to_owned(), account.to_owned()));
    }
}

#[async_trait]
impl Keychain for MockKeychainAdapter {
    /// Store `secret` under `(service, account)`.
    ///
    /// Also updates the sentinel index for `service` so that [`Self::list`]
    /// returns the account.  The sentinel entry itself is never added to its
    /// own index.
    ///
    /// Returns `KeychainError::PersistenceFailed` if the key was registered
    /// via [`Self::with_persistence_failure_for`] (ADR-0015 Amendment 4 test
    /// support).
    async fn store(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), KeychainError> {
        debug!(service, account, bytes = secret.len(), "mock keychain store");
        // Check global write-unavailable flag.
        if *self.write_unavailable.lock() {
            return Err(KeychainError::Backend("keychain_unavailable".into()));
        }
        // Check persistence-failure injection (ADR-0015 Amendment 4).
        if self
            .persistence_failures
            .lock()
            .contains(&(service.to_owned(), account.to_owned()))
        {
            return Err(KeychainError::PersistenceFailed {
                service: service.to_owned(),
                account: account.to_owned(),
            });
        }
        let mut guard = self.store.lock();
        guard.insert((service.to_owned(), account.to_owned()), secret.to_vec());

        // Update the account index (skip indexing the sentinel itself).
        if !account.ends_with(INDEX_SUFFIX) {
            let sentinel = sentinel_account(service);
            let raw = guard
                .get(&(service.to_owned(), sentinel.clone()))
                .cloned()
                .unwrap_or_default();
            let mut index = decode_index(&raw)?;
            if index_add(&mut index, account) {
                let encoded = encode_index(&index)?;
                guard.insert((service.to_owned(), sentinel), encoded);
            }
        }
        Ok(())
    }

    /// Retrieve the secret stored under `(service, account)`.
    ///
    /// Returns [`KeychainError::NotFound`] if no entry exists.
    async fn retrieve(&self, service: &str, account: &str) -> Result<Vec<u8>, KeychainError> {
        debug!(service, account, "mock keychain retrieve");
        // Check injected errors first.
        if let Some(injected) = self
            .injected_errors
            .lock()
            .get(&(service.to_owned(), account.to_owned()))
            .copied()
        {
            return match injected {
                // PersistenceFailed is a store-side injection; retrieve still
                // returns NotFound so callers can observe the expected behaviour.
                InjectedError::NotFound | InjectedError::PersistenceFailed => {
                    Err(KeychainError::NotFound)
                }
                InjectedError::Unavailable => {
                    Err(KeychainError::Backend("keychain_unavailable".into()))
                }
            };
        }
        self.store
            .lock()
            .get(&(service.to_owned(), account.to_owned()))
            .cloned()
            .ok_or(KeychainError::NotFound)
    }

    /// Delete the entry for `(service, account)`.
    ///
    /// Returns [`KeychainError::NotFound`] if no entry exists.
    /// Also removes the account from the sentinel index.
    async fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError> {
        debug!(service, account, "mock keychain delete");
        let mut guard = self.store.lock();
        if guard
            .remove(&(service.to_owned(), account.to_owned()))
            .is_none()
        {
            return Err(KeychainError::NotFound);
        }

        // Remove from index (skip if the sentinel itself is being deleted).
        if !account.ends_with(INDEX_SUFFIX) {
            let sentinel = sentinel_account(service);
            let raw = guard
                .get(&(service.to_owned(), sentinel.clone()))
                .cloned()
                .unwrap_or_default();
            let mut index = decode_index(&raw)?;
            if index_remove(&mut index, account) {
                let encoded = encode_index(&index)?;
                guard.insert((service.to_owned(), sentinel), encoded);
            }
        }
        Ok(())
    }

    /// List all accounts stored under `service`.
    ///
    /// Reads the sentinel index entry and returns the decoded list.  If no
    /// entries have ever been stored for `service`, returns an empty vec.
    async fn list(&self, service: &str) -> Result<Vec<String>, KeychainError> {
        debug!(service, "mock keychain list");
        let guard = self.store.lock();
        let sentinel = sentinel_account(service);
        let raw = guard
            .get(&(service.to_owned(), sentinel))
            .cloned()
            .unwrap_or_default();
        decode_index(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_with_persistence_failure_injection_returns_persistence_failed() {
        let mock = MockKeychainAdapter::new();
        mock.with_persistence_failure_for("merkle-test", "mk");

        let result = mock.store("merkle-test", "mk", &[1u8; 32]).await;

        assert!(
            matches!(result, Err(KeychainError::PersistenceFailed { .. })),
            "expected PersistenceFailed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn store_without_injection_persists_and_retrieves_correctly() {
        let mock = MockKeychainAdapter::new();
        let secret = [0xAB_u8; 32];

        mock.store("svc", "acct", &secret).await.expect("store ok");
        let retrieved = mock.retrieve("svc", "acct").await.expect("retrieve ok");

        assert_eq!(retrieved, secret.to_vec());
    }

    #[tokio::test]
    async fn clear_persistence_failure_allows_subsequent_store() {
        let mock = MockKeychainAdapter::new();
        mock.with_persistence_failure_for("svc", "acct");

        // First store should fail.
        let first = mock.store("svc", "acct", &[1u8; 32]).await;
        assert!(matches!(first, Err(KeychainError::PersistenceFailed { .. })));

        // After clearing the injection, store should succeed.
        mock.clear_persistence_failure_for("svc", "acct");
        mock.store("svc", "acct", &[2u8; 32])
            .await
            .expect("store after clear should succeed");
        let retrieved = mock.retrieve("svc", "acct").await.expect("retrieve ok");
        assert_eq!(retrieved, vec![2u8; 32]);
    }
}
