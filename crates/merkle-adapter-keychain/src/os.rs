//! OS keychain adapter backed by the `keyring` crate.
//!
//! `OsKeychainAdapter` wraps `keyring::Entry` and dispatches to the native
//! credential store on each platform:
//!
//! - **macOS**: Security framework (login keychain).
//! - **Linux**: Secret Service (libsecret / GNOME Keyring) or KWallet.
//! - **Windows**: Credential Manager (`wincred`).
//!
//! All `keyring` calls are synchronous.  To avoid blocking the Tokio executor
//! each call is wrapped in [`tokio::task::spawn_blocking`].
//!
//! ## Binary secrets and base64 encoding
//!
//! The `keyring` crate stores secrets as byte slices via `set_secret` /
//! `get_secret`, which avoids the UTF-8 restriction of the older `set_password`
//! / `get_password` API.  We use the binary API directly so no base64
//! round-trip is needed in the adapter itself.
//!
//! ## Account index sentinel
//!
//! `keyring` has no native `list` operation.  We maintain a sentinel entry
//! under `<service>__merkle_account_index` (see [`crate::index`]) to track
//! which accounts exist for a given service.

use async_trait::async_trait;
use merkle_ports::{Keychain, KeychainError};
use tracing::{debug, warn};

use crate::index::{
    INDEX_SUFFIX, decode_index, encode_index, index_add, index_remove, sentinel_account,
};

/// Production keychain adapter backed by the OS keychain.
///
/// The struct holds no state — each operation constructs a short-lived
/// `keyring::Entry` and interacts with the OS.  It is `Clone` and `Default`
/// so it can be cheaply stored in application state.
#[derive(Debug, Clone, Default)]
pub struct OsKeychainAdapter;

impl OsKeychainAdapter {
    /// Create a new adapter.
    pub fn new() -> Self {
        Self
    }
}

/// Map a `keyring::Error` to a `KeychainError`.
fn map_err(err: keyring::Error) -> KeychainError {
    match err {
        keyring::Error::NoEntry => KeychainError::NotFound,
        keyring::Error::NoStorageAccess(_) => KeychainError::Backend("no storage access".into()),
        other => KeychainError::Backend(other.to_string()),
    }
}

#[async_trait]
impl Keychain for OsKeychainAdapter {
    /// Store `secret` under `(service, account)` in the OS keychain.
    ///
    /// Also updates the sentinel account-index entry so that [`Self::list`]
    /// returns the account.
    ///
    /// # Persistence verification (ADR-0015 Amendment 4)
    ///
    /// After the write call returns, this method immediately performs a
    /// `retrieve()` and compares the round-tripped bytes against `secret`.
    /// If the retrieve returns `NotFound` or different bytes, the write is
    /// considered a silent failure and `KeychainError::PersistenceFailed` is
    /// returned. This guards against the macOS Security framework silently
    /// no-opping writes in background processes without GUI auth.
    async fn store(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), KeychainError> {
        debug!(service, account, bytes = secret.len(), "os keychain store");
        let service_owned = service.to_owned();
        let account_owned = account.to_owned();
        let secret_owned = secret.to_vec();

        // Step 1: write via spawn_blocking (keyring is sync).
        tokio::task::spawn_blocking(move || -> Result<(), KeychainError> {
            // Write the actual secret.
            let entry = keyring::Entry::new(&service_owned, &account_owned).map_err(map_err)?;
            entry.set_secret(&secret_owned).map_err(map_err)?;

            // Update the account index (skip indexing the sentinel itself).
            if !account_owned.ends_with(INDEX_SUFFIX) {
                update_index_add(&service_owned, &account_owned)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| KeychainError::Backend(format!("spawn_blocking join: {e}")))??;

        // Step 2: verify persistence (per ADR-0015 Amendment 4).
        // A retrieve immediately after a successful write that returns NotFound
        // or different bytes indicates a silent no-op by the OS (e.g., macOS
        // background process without keychain access permission).
        let verified = self.retrieve(service, account).await;
        match verified {
            Ok(ref retrieved) if retrieved == secret => {
                debug!(service, account, "os keychain store: persistence verified");
                Ok(())
            }
            Ok(_) => {
                warn!(
                    service,
                    account,
                    "os keychain store: retrieved bytes differ from written bytes —                      write silently failed (persistence_failed)"
                );
                Err(KeychainError::PersistenceFailed {
                    service: service.to_owned(),
                    account: account.to_owned(),
                })
            }
            Err(KeychainError::NotFound) => {
                warn!(
                    service,
                    account,
                    "os keychain store: entry not found after write —                      write silently no-oped (persistence_failed)"
                );
                Err(KeychainError::PersistenceFailed {
                    service: service.to_owned(),
                    account: account.to_owned(),
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Retrieve the secret stored under `(service, account)` from the OS keychain.
    async fn retrieve(&self, service: &str, account: &str) -> Result<Vec<u8>, KeychainError> {
        debug!(service, account, "os keychain retrieve");
        let service = service.to_owned();
        let account = account.to_owned();

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, KeychainError> {
            let entry = keyring::Entry::new(&service, &account).map_err(map_err)?;
            entry.get_secret().map_err(map_err)
        })
        .await
        .map_err(|e| KeychainError::Backend(format!("spawn_blocking join: {e}")))?
    }

    /// Delete the entry for `(service, account)` from the OS keychain.
    ///
    /// Returns [`KeychainError::NotFound`] if no entry exists.
    /// Also removes the account from the sentinel index.
    async fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError> {
        debug!(service, account, "os keychain delete");
        let service = service.to_owned();
        let account = account.to_owned();

        tokio::task::spawn_blocking(move || -> Result<(), KeychainError> {
            let entry = keyring::Entry::new(&service, &account).map_err(map_err)?;
            entry.delete_credential().map_err(map_err)?;

            if !account.ends_with(INDEX_SUFFIX) {
                update_index_remove(&service, &account)?;
            }
            Ok(())
        })
        .await
        .map_err(|e| KeychainError::Backend(format!("spawn_blocking join: {e}")))?
    }

    /// List all accounts stored under `service` by reading the sentinel index.
    async fn list(&self, service: &str) -> Result<Vec<String>, KeychainError> {
        debug!(service, "os keychain list");
        let service = service.to_owned();

        tokio::task::spawn_blocking(move || -> Result<Vec<String>, KeychainError> {
            let sentinel = sentinel_account(&service);
            let entry = keyring::Entry::new(&service, &sentinel).map_err(map_err)?;
            match entry.get_secret() {
                Ok(raw) => decode_index(&raw),
                Err(keyring::Error::NoEntry) => Ok(Vec::new()),
                Err(e) => Err(map_err(e)),
            }
        })
        .await
        .map_err(|e| KeychainError::Backend(format!("spawn_blocking join: {e}")))?
    }
}

/// Read the current index for `service`, add `account`, and write back.
fn update_index_add(service: &str, account: &str) -> Result<(), KeychainError> {
    let sentinel = sentinel_account(service);
    let entry = keyring::Entry::new(service, &sentinel).map_err(map_err)?;
    let raw = match entry.get_secret() {
        Ok(bytes) => bytes,
        Err(keyring::Error::NoEntry) => Vec::new(),
        Err(e) => return Err(map_err(e)),
    };
    let mut index = decode_index(&raw)?;
    if index_add(&mut index, account) {
        let encoded = encode_index(&index)?;
        entry.set_secret(&encoded).map_err(map_err)?;
    }
    Ok(())
}

/// Read the current index for `service`, remove `account`, and write back.
fn update_index_remove(service: &str, account: &str) -> Result<(), KeychainError> {
    let sentinel = sentinel_account(service);
    let entry = keyring::Entry::new(service, &sentinel).map_err(map_err)?;
    let raw = match entry.get_secret() {
        Ok(bytes) => bytes,
        Err(keyring::Error::NoEntry) => {
            warn!(service, account, "index sentinel missing on delete");
            return Ok(());
        }
        Err(e) => return Err(map_err(e)),
    };
    let mut index = decode_index(&raw)?;
    if index_remove(&mut index, account) {
        let encoded = encode_index(&index)?;
        entry.set_secret(&encoded).map_err(map_err)?;
    }
    Ok(())
}
