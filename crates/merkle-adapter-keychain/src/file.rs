//! File-backed keystore adapter encrypted with `age` (ADR-0022).
//!
//! [`FileKeystoreAdapter`] implements [`merkle_ports::Keychain`] by persisting
//! secrets to a single age-encrypted JSON file at a configurable path.  It is
//! intended for CI/headless/Docker contexts where no OS keychain is available.
//!
//! ## Storage format
//!
//! ```text
//! path: ~/.local/share/merkle/keystore.age  (or $MERKLE_KEYSTORE_PATH)
//! ```
//!
//! The plaintext inside the age envelope is a JSON object:
//!
//! ```json
//! {
//!   "<service>": {
//!     "<account>": "<standard-base64 of secret bytes>"
//!   }
//! }
//! ```
//!
//! ## Encryption
//!
//! `age` passphrase-based encryption (`Encryptor::with_user_passphrase`).
//! The passphrase is supplied via `MERKLE_KEYSTORE_PASSPHRASE` env var or an
//! `rpassword` TTY prompt.
//!
//! ## Concurrency
//!
//! An in-process `tokio::sync::Mutex` guards the in-memory snapshot.
//! Each mutation holds the lock for the entire mutate+persist cycle so no
//! concurrent writer can interleave a partial snapshot.
//!
//! ## Atomic writes
//!
//! Every `persist` call writes to `<path>.tmp` then renames it into place.
//! This prevents corrupt-on-crash scenarios.
//!
//! ## Corruption
//!
//! If age decryption fails on `open`, the function returns
//! `KeychainError::Backend` with a descriptive message.  The adapter never
//! silently overwrites a file it cannot decrypt.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;

use async_trait::async_trait;
use merkle_ports::{Keychain, KeychainError};
use secrecy::ExposeSecret as _;
use tracing::debug;

use crate::index::{
    decode_index, encode_index, index_add, index_remove, sentinel_account, INDEX_SUFFIX,
};

/// Key type for the in-memory snapshot: `(service, account)`.
type StoreKey = (String, String);

/// Snapshot type: outer key = service, inner = account → base64 secret.
type Snapshot = HashMap<String, HashMap<String, String>>;

/// File-backed keystore adapter.
///
/// All secrets are persisted to an age-encrypted JSON file.  The in-memory
/// `HashMap` is kept in sync with the on-disk file; each write atomically
/// re-encrypts and replaces the file.
///
/// # Example
///
/// ```rust,no_run
/// # use std::path::PathBuf;
/// # use secrecy::SecretString;
/// # use merkle_adapter_keychain::FileKeystoreAdapter;
/// # #[tokio::main]
/// # async fn main() {
/// let path = PathBuf::from("/tmp/test-keystore.age");
/// let passphrase = SecretString::new("my-secret-passphrase".to_owned().into());
/// let adapter = FileKeystoreAdapter::open(path, passphrase).await.expect("open ok");
/// # }
/// ```
#[derive(Debug)]
pub struct FileKeystoreAdapter {
    path: PathBuf,
    /// Passphrase kept in memory to re-encrypt on each persist.
    passphrase: secrecy::SecretString,
    /// In-memory snapshot guarded by a Tokio mutex.
    inner: tokio::sync::Mutex<HashMap<StoreKey, Vec<u8>>>,
}

impl FileKeystoreAdapter {
    /// Open (or create) a file keystore at `path`, decrypting with `passphrase`.
    ///
    /// - If the file does not exist, an empty store is created (no disk write
    ///   until the first `store` call).
    /// - If the file exists, it is decrypted and the snapshot loaded.  An age
    ///   decryption failure (wrong passphrase, corrupt file) returns
    ///   [`KeychainError::Backend`] immediately — the adapter refuses to
    ///   proceed with unverifiable data.
    ///
    /// All blocking I/O is offloaded to `tokio::task::spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainError::Backend`] when the file exists but cannot be
    /// decrypted or parsed.
    pub async fn open(
        path: PathBuf,
        passphrase: secrecy::SecretString,
    ) -> Result<Self, KeychainError> {
        let path2 = path.clone();
        // Clone the passphrase into the blocking closure; secrecy::SecretString
        // is not Clone so we expose and re-wrap.
        let passphrase_str = {
            use secrecy::ExposeSecret as _;
            passphrase.expose_secret().to_owned()
        };

        let snapshot = tokio::task::spawn_blocking(move || {
            if path2.exists() {
                let p = secrecy::SecretString::new(passphrase_str.into());
                load_snapshot(&path2, &p)
            } else {
                debug!(path = %path2.display(), "file keystore: no file found, starting empty");
                Ok(HashMap::new())
            }
        })
        .await
        .map_err(|e| KeychainError::Backend(format!("spawn_blocking join: {e}")))??;

        Ok(Self {
            path,
            passphrase,
            inner: tokio::sync::Mutex::new(snapshot),
        })
    }

    /// Atomically persist the current in-memory snapshot to disk.
    ///
    /// Serializes to JSON, encrypts with age, then writes to `<path>.tmp` and
    /// renames it into place.  The rename is atomic on POSIX; the tmp and final
    /// file share the same directory to satisfy that requirement.
    ///
    /// All blocking I/O is performed via `tokio::task::spawn_blocking`.
    async fn persist(
        &self,
        snapshot: &HashMap<StoreKey, Vec<u8>>,
    ) -> Result<(), KeychainError> {
        use secrecy::ExposeSecret as _;

        // Rebuild the nested JSON structure (in async context — pure CPU, fast).
        let mut nested: Snapshot = HashMap::new();
        for ((service, account), secret) in snapshot {
            nested
                .entry(service.clone())
                .or_default()
                .insert(
                    account.clone(),
                    base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        secret,
                    ),
                );
        }

        let plaintext = serde_json::to_vec(&nested)
            .map_err(|e| KeychainError::Backend(format!("serialize snapshot: {e}")))?;

        // Clone data needed in the blocking closure.
        let passphrase_str = self.passphrase.expose_secret().to_owned();
        let path = self.path.clone();

        tokio::task::spawn_blocking(move || {
            let passphrase = secrecy::SecretString::new(passphrase_str.into());
            let ciphertext = age_encrypt(&plaintext, &passphrase)?;

            let tmp_path = path.with_extension("age.tmp");
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    KeychainError::Backend(format!(
                        "create keystore directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }
            std::fs::write(&tmp_path, &ciphertext).map_err(|e| {
                KeychainError::Backend(format!("write tmp {}: {e}", tmp_path.display()))
            })?;
            std::fs::rename(&tmp_path, &path).map_err(|e| {
                KeychainError::Backend(format!(
                    "rename tmp → keystore {}: {e}",
                    path.display()
                ))
            })?;
            debug!(path = %path.display(), "file keystore: persisted");
            Ok(())
        })
        .await
        .map_err(|e| KeychainError::Backend(format!("spawn_blocking join (persist): {e}")))?
    }
}

// ---------------------------------------------------------------------------
// Keychain trait impl
// ---------------------------------------------------------------------------

#[async_trait]
impl Keychain for FileKeystoreAdapter {
    /// Store `secret` under `(service, account)` and persist to disk.
    ///
    /// Also updates the sentinel account-index entry so that [`Self::list`]
    /// returns the account.
    async fn store(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), KeychainError> {
        debug!(service, account, bytes = secret.len(), "file keystore store");
        let mut guard = self.inner.lock().await;

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

        self.persist(&guard).await
    }

    /// Retrieve the secret stored under `(service, account)`.
    ///
    /// Returns [`KeychainError::NotFound`] if no entry exists.
    async fn retrieve(&self, service: &str, account: &str) -> Result<Vec<u8>, KeychainError> {
        debug!(service, account, "file keystore retrieve");
        let guard = self.inner.lock().await;
        guard
            .get(&(service.to_owned(), account.to_owned()))
            .cloned()
            .ok_or(KeychainError::NotFound)
    }

    /// Delete the entry for `(service, account)` and persist to disk.
    ///
    /// Returns [`KeychainError::NotFound`] if no entry exists.
    /// Also removes the account from the sentinel index.
    async fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError> {
        debug!(service, account, "file keystore delete");
        let mut guard = self.inner.lock().await;

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

        self.persist(&guard).await
    }

    /// List all accounts stored under `service` by reading the sentinel index.
    async fn list(&self, service: &str) -> Result<Vec<String>, KeychainError> {
        debug!(service, "file keystore list");
        let guard = self.inner.lock().await;
        let sentinel = sentinel_account(service);
        let raw = guard
            .get(&(service.to_owned(), sentinel))
            .cloned()
            .unwrap_or_default();
        decode_index(&raw)
    }
}

// ---------------------------------------------------------------------------
// age helpers
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with `passphrase` using age passphrase-based encryption.
fn age_encrypt(plaintext: &[u8], passphrase: &secrecy::SecretString) -> Result<Vec<u8>, KeychainError> {
    // age uses its own re-exported secrecy crate (0.8); we bridge via expose_secret.
    let age_passphrase = age::secrecy::SecretString::new(
        passphrase.expose_secret().to_owned(),
    );
    let encryptor = age::Encryptor::with_user_passphrase(age_passphrase);
    let mut ciphertext: Vec<u8> = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| KeychainError::Backend(format!("age wrap_output: {e}")))?;
    writer
        .write_all(plaintext)
        .map_err(|e| KeychainError::Backend(format!("age write: {e}")))?;
    writer
        .finish()
        .map_err(|e| KeychainError::Backend(format!("age finish: {e}")))?;
    Ok(ciphertext)
}

/// Decrypt age ciphertext with `passphrase`.  Returns the plaintext bytes.
fn age_decrypt(ciphertext: &[u8], passphrase: &secrecy::SecretString) -> Result<Vec<u8>, KeychainError> {
    let age_passphrase = age::secrecy::SecretString::new(
        passphrase.expose_secret().to_owned(),
    );
    let decryptor =
        age::Decryptor::new(ciphertext)
            .map_err(|e| KeychainError::Backend(format!("age decryptor: {e}")))?;
    match decryptor {
        age::Decryptor::Passphrase(d) => {
            let mut reader = d
                .decrypt(&age_passphrase, None)
                .map_err(|e| KeychainError::Backend(format!("age decrypt: {e}")))?;
            let mut plaintext = Vec::new();
            reader
                .read_to_end(&mut plaintext)
                .map_err(|e| KeychainError::Backend(format!("age read: {e}")))?;
            Ok(plaintext)
        }
        age::Decryptor::Recipients(_) => Err(KeychainError::Backend(
            "keystore file uses recipient-based encryption; expected passphrase".to_owned(),
        )),
    }
}

/// Load a flat `HashMap<StoreKey, Vec<u8>>` from an age-encrypted JSON file.
fn load_snapshot(
    path: &PathBuf,
    passphrase: &secrecy::SecretString,
) -> Result<HashMap<StoreKey, Vec<u8>>, KeychainError> {
    let ciphertext = std::fs::read(path).map_err(|e| {
        KeychainError::Backend(format!("read keystore {}: {e}", path.display()))
    })?;

    let plaintext = age_decrypt(&ciphertext, passphrase)?;

    let nested: Snapshot = serde_json::from_slice(&plaintext).map_err(|e| {
        KeychainError::Backend(format!("parse keystore JSON: {e}"))
    })?;

    let mut flat: HashMap<StoreKey, Vec<u8>> = HashMap::new();
    for (service, accounts) in nested {
        for (account, b64) in accounts {
            let secret = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
                .map_err(|e| {
                    KeychainError::Backend(format!(
                        "base64 decode for ({service}, {account}): {e}"
                    ))
                })?;
            flat.insert((service.clone(), account), secret);
        }
    }

    debug!(
        path = %path.display(),
        entries = flat.len(),
        "file keystore: loaded snapshot"
    );
    Ok(flat)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use tempfile::TempDir;

    use merkle_ports::Keychain;

    use super::*;

    fn passphrase(s: &str) -> SecretString {
        SecretString::new(s.to_owned().into())
    }

    async fn open_tmp(dir: &TempDir, phrase: &str) -> FileKeystoreAdapter {
        let path = dir.path().join("keystore.age");
        FileKeystoreAdapter::open(path, passphrase(phrase))
            .await
            .expect("open should succeed")
    }

    // -- round-trip -----------------------------------------------------------

    #[tokio::test]
    async fn store_retrieve_round_trip() {
        let dir = TempDir::new().expect("tempdir");
        let adapter = open_tmp(&dir, "passphrase").await;
        let secret = vec![0xAB_u8; 32];

        adapter
            .store("svc", "acct", &secret)
            .await
            .expect("store ok");
        let got = adapter.retrieve("svc", "acct").await.expect("retrieve ok");
        assert_eq!(got, secret);
    }

    #[tokio::test]
    async fn retrieve_missing_returns_not_found() {
        let dir = TempDir::new().expect("tempdir");
        let adapter = open_tmp(&dir, "passphrase").await;
        let err = adapter.retrieve("svc", "absent").await.unwrap_err();
        assert!(
            matches!(err, KeychainError::NotFound),
            "expected NotFound, got {err:?}"
        );
    }

    // -- list -----------------------------------------------------------------

    #[tokio::test]
    async fn list_returns_stored_accounts() {
        let dir = TempDir::new().expect("tempdir");
        let adapter = open_tmp(&dir, "passphrase").await;

        adapter
            .store("svc", "master-v1", &[1u8; 32])
            .await
            .expect("store 1");
        adapter
            .store("svc", "master-v2", &[2u8; 32])
            .await
            .expect("store 2");

        let mut list = adapter.list("svc").await.expect("list ok");
        list.sort();
        assert_eq!(list, ["master-v1", "master-v2"]);
    }

    #[tokio::test]
    async fn list_empty_service_returns_empty_vec() {
        let dir = TempDir::new().expect("tempdir");
        let adapter = open_tmp(&dir, "passphrase").await;
        let list = adapter.list("svc").await.expect("list ok");
        assert!(list.is_empty());
    }

    // -- delete ---------------------------------------------------------------

    #[tokio::test]
    async fn delete_removes_entry_and_index() {
        let dir = TempDir::new().expect("tempdir");
        let adapter = open_tmp(&dir, "passphrase").await;

        adapter
            .store("svc", "acct", &[1u8; 16])
            .await
            .expect("store");
        adapter.delete("svc", "acct").await.expect("delete ok");

        let err = adapter.retrieve("svc", "acct").await.unwrap_err();
        assert!(matches!(err, KeychainError::NotFound));

        let list = adapter.list("svc").await.expect("list ok");
        assert!(!list.contains(&"acct".to_owned()));
    }

    #[tokio::test]
    async fn delete_absent_returns_not_found() {
        let dir = TempDir::new().expect("tempdir");
        let adapter = open_tmp(&dir, "passphrase").await;
        let err = adapter.delete("svc", "absent").await.unwrap_err();
        assert!(matches!(err, KeychainError::NotFound));
    }

    // -- persistence (survive reload) ----------------------------------------

    #[tokio::test]
    async fn data_survives_reload() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("keystore.age");
        let secret = vec![0xDE_u8, 0xAD_u8, 0xBE_u8, 0xEF_u8];

        // Write with first adapter.
        {
            let a = FileKeystoreAdapter::open(path.clone(), passphrase("ph"))
                .await
                .expect("open1");
            a.store("dev.fapp.merkle", "master-v1", &secret)
                .await
                .expect("store");
        }

        // Re-open from same file.
        let b = FileKeystoreAdapter::open(path, passphrase("ph"))
            .await
            .expect("open2");
        let got = b
            .retrieve("dev.fapp.merkle", "master-v1")
            .await
            .expect("retrieve after reload");
        assert_eq!(got, secret);
    }

    #[tokio::test]
    async fn wrong_passphrase_on_reload_returns_backend_error() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("keystore.age");

        // Create the file with correct passphrase.
        {
            let a = FileKeystoreAdapter::open(path.clone(), passphrase("correct"))
                .await
                .expect("open");
            a.store("svc", "acct", &[1u8; 4])
                .await
                .expect("store");
        }

        // Re-open with wrong passphrase.
        let err = FileKeystoreAdapter::open(path, passphrase("wrong"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, KeychainError::Backend(_)),
            "expected Backend error on wrong passphrase, got {err:?}"
        );
    }

    // -- index idempotency ---------------------------------------------------

    #[tokio::test]
    async fn store_same_account_twice_appears_once_in_index() {
        let dir = TempDir::new().expect("tempdir");
        let adapter = open_tmp(&dir, "passphrase").await;

        adapter
            .store("svc", "acct", &[1u8; 4])
            .await
            .expect("first store");
        adapter
            .store("svc", "acct", &[2u8; 4])
            .await
            .expect("second store");

        let list = adapter.list("svc").await.expect("list");
        assert_eq!(
            list.iter().filter(|a| a.as_str() == "acct").count(),
            1,
            "account should appear exactly once in index"
        );
    }
}
