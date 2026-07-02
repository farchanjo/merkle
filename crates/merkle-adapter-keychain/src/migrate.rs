//! One-way keystore migration between two [`Keychain`] backends.
//!
//! Used by the agent composition root to move existing entries (e.g. the
//! wrapped VRK blobs) from the age-encrypted file keystore into the OS
//! keychain once the OS backend becomes usable (ADR-0015 / ADR-0029).
//!
//! The migration is **copy-only**: source entries are never deleted, so the
//! operator can keep the file keystore as a cold backup and remove it
//! manually after verifying the new backend.

use merkle_ports::{Keychain, KeychainError};
use tracing::info;

/// Copy every account under `service` from `src` into `dst`.
///
/// Accounts that already exist in `dst` are left untouched (the destination
/// wins — migration never overwrites). Returns the list of account names
/// actually copied.
///
/// # Errors
///
/// Returns the first [`KeychainError`] encountered while listing, reading,
/// or writing. Entries copied before the failure remain in `dst` (the
/// operation is idempotent and can simply be re-run).
pub async fn migrate_accounts(
    src: &dyn Keychain,
    dst: &dyn Keychain,
    service: &str,
) -> Result<Vec<String>, KeychainError> {
    let mut copied = Vec::new();
    for account in src.list(service).await? {
        match dst.retrieve(service, &account).await {
            Ok(_) => continue, // destination already has it — never overwrite
            Err(KeychainError::NotFound) => {}
            Err(e) => return Err(e),
        }
        let secret = src.retrieve(service, &account).await?;
        dst.store(service, &account, &secret).await?;
        info!(service, account, "keystore migration: account copied");
        copied.push(account);
    }
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockKeychainAdapter;

    const SVC: &str = "dev.fapp.merkle.migrate-test";

    #[tokio::test]
    async fn copies_all_accounts_and_preserves_source() {
        let src = MockKeychainAdapter::new();
        let dst = MockKeychainAdapter::new();
        src.store(SVC, "vrk-master-v1", b"master-blob")
            .await
            .unwrap();
        src.store(SVC, "vrk-recovery-v1", b"recovery-blob")
            .await
            .unwrap();

        let mut copied = migrate_accounts(&src, &dst, SVC).await.unwrap();
        copied.sort();
        assert_eq!(copied, vec!["vrk-master-v1", "vrk-recovery-v1"]);
        assert_eq!(
            dst.retrieve(SVC, "vrk-master-v1").await.unwrap(),
            b"master-blob"
        );
        assert_eq!(
            dst.retrieve(SVC, "vrk-recovery-v1").await.unwrap(),
            b"recovery-blob"
        );
        // copy-only: source untouched
        assert_eq!(
            src.retrieve(SVC, "vrk-master-v1").await.unwrap(),
            b"master-blob"
        );
    }

    #[tokio::test]
    async fn never_overwrites_existing_destination_entry() {
        let src = MockKeychainAdapter::new();
        let dst = MockKeychainAdapter::new();
        src.store(SVC, "vrk-master-v1", b"from-file").await.unwrap();
        dst.store(SVC, "vrk-master-v1", b"already-in-os")
            .await
            .unwrap();

        let copied = migrate_accounts(&src, &dst, SVC).await.unwrap();
        assert!(copied.is_empty());
        assert_eq!(
            dst.retrieve(SVC, "vrk-master-v1").await.unwrap(),
            b"already-in-os"
        );
    }

    #[tokio::test]
    async fn empty_source_is_a_noop() {
        let src = MockKeychainAdapter::new();
        let dst = MockKeychainAdapter::new();
        let copied = migrate_accounts(&src, &dst, SVC).await.unwrap();
        assert!(copied.is_empty());
    }
}
