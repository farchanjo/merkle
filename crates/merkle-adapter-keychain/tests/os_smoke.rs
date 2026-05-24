//! OS keychain smoke tests.
//!
//! These tests interact with the real OS keychain and are marked `#[ignore]` so
//! they are skipped in CI by default.  Run them manually with:
//!
//! ```sh
//! cargo test -p merkle-adapter-keychain --test os_smoke -- --ignored
//! ```
//!
//! Each test uses a unique service name (`dev.fapp.merkle.smoke.<timestamp>`)
//! to avoid collisions with production entries, and cleans up after itself.

use merkle_adapter_keychain::OsKeychainAdapter;
use merkle_ports::{Keychain, KeychainError};

fn smoke_service() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros());
    format!("dev.fapp.merkle.smoke.{ts}")
}

#[tokio::test]
#[ignore = "requires OS keychain; run manually with --ignored"]
async fn os_store_retrieve_delete_roundtrip() {
    let kc = OsKeychainAdapter::new();
    let svc = smoke_service();
    let account = "smoke-v1";
    let secret = b"merkle-smoke-test-32-byte-secret";

    // Store.
    kc.store(&svc, account, secret)
        .await
        .expect("store should succeed");

    // Retrieve.
    let got = kc
        .retrieve(&svc, account)
        .await
        .expect("retrieve should succeed");
    assert_eq!(got, secret, "round-trip bytes must match");

    // List.
    let accounts = kc.list(&svc).await.expect("list should succeed");
    assert!(
        accounts.contains(&account.to_owned()),
        "list must include stored account"
    );

    // Delete.
    kc.delete(&svc, account)
        .await
        .expect("delete should succeed");

    // Retrieve after delete.
    let err = kc.retrieve(&svc, account).await.unwrap_err();
    assert!(
        matches!(err, KeychainError::NotFound),
        "should be NotFound after delete"
    );
}

#[tokio::test]
#[ignore = "requires OS keychain; run manually with --ignored"]
async fn os_delete_nonexistent_returns_not_found() {
    let kc = OsKeychainAdapter::new();
    let svc = smoke_service();
    let err = kc.delete(&svc, "ghost-key").await.unwrap_err();
    assert!(matches!(err, KeychainError::NotFound));
}

#[tokio::test]
#[ignore = "requires OS keychain; run manually with --ignored"]
async fn os_list_empty_for_unknown_service() {
    let kc = OsKeychainAdapter::new();
    let svc = smoke_service();
    let accounts = kc
        .list(&svc)
        .await
        .expect("list should not error for empty service");
    assert!(accounts.is_empty());
}
