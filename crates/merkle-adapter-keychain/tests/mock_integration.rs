//! Integration tests for `MockKeychainAdapter`.
//!
//! These tests cover all `Keychain` operations and verify that the account-index
//! sentinel is maintained correctly.  No OS keychain is required; all state is
//! in-memory.

use merkle_adapter_keychain::MockKeychainAdapter;
use merkle_ports::{Keychain, KeychainError};

const SVC: &str = "dev.fapp.merkle.test";

// ── store + retrieve round-trip ──────────────────────────────────────────────

#[tokio::test]
async fn store_retrieve_roundtrip() {
    let kc = MockKeychainAdapter::new();
    let secret = b"hunter2-but-32-bytes-of-data!!x";
    kc.store(SVC, "master-v1", secret).await.unwrap();
    let got = kc.retrieve(SVC, "master-v1").await.unwrap();
    assert_eq!(got, secret);
}

// ── binary secrets (non-UTF-8) ───────────────────────────────────────────────

#[tokio::test]
async fn store_and_retrieve_binary_secret() {
    let kc = MockKeychainAdapter::new();
    // 32 bytes that are not valid UTF-8.
    let secret: Vec<u8> = (0u8..=31).collect();
    kc.store(SVC, "binary-key", &secret).await.unwrap();
    let got = kc.retrieve(SVC, "binary-key").await.unwrap();
    assert_eq!(got, secret);
}

// ── list returns all stored accounts ─────────────────────────────────────────

#[tokio::test]
async fn list_returns_all_accounts() {
    let kc = MockKeychainAdapter::new();
    kc.store(SVC, "master-v1", b"secret1").await.unwrap();
    kc.store(SVC, "master-v2", b"secret2").await.unwrap();

    let mut accounts = kc.list(SVC).await.unwrap();
    accounts.sort();
    assert_eq!(accounts, ["master-v1", "master-v2"]);
}

// ── list returns empty vec for unknown service ────────────────────────────────

#[tokio::test]
async fn list_unknown_service_returns_empty() {
    let kc = MockKeychainAdapter::new();
    let accounts = kc.list("no.such.service").await.unwrap();
    assert!(accounts.is_empty());
}

// ── delete removes entry and updates index ────────────────────────────────────

#[tokio::test]
async fn delete_removes_from_index() {
    let kc = MockKeychainAdapter::new();
    kc.store(SVC, "master-v1", b"secret").await.unwrap();
    kc.store(SVC, "master-v2", b"secret2").await.unwrap();

    kc.delete(SVC, "master-v1").await.unwrap();

    let accounts = kc.list(SVC).await.unwrap();
    assert!(
        !accounts.contains(&"master-v1".to_owned()),
        "master-v1 must be gone"
    );
    assert!(
        accounts.contains(&"master-v2".to_owned()),
        "master-v2 must remain"
    );
}

#[tokio::test]
async fn delete_then_retrieve_returns_not_found() {
    let kc = MockKeychainAdapter::new();
    kc.store(SVC, "master-v1", b"secret").await.unwrap();
    kc.delete(SVC, "master-v1").await.unwrap();

    let err = kc.retrieve(SVC, "master-v1").await.unwrap_err();
    assert!(
        matches!(err, KeychainError::NotFound),
        "expected NotFound, got {err:?}"
    );
}

// ── delete non-existent returns NotFound ──────────────────────────────────────

#[tokio::test]
async fn delete_nonexistent_returns_not_found() {
    let kc = MockKeychainAdapter::new();
    let err = kc.delete(SVC, "ghost-key").await.unwrap_err();
    assert!(
        matches!(err, KeychainError::NotFound),
        "expected NotFound, got {err:?}"
    );
}

// ── retrieve non-existent returns NotFound ────────────────────────────────────

#[tokio::test]
async fn retrieve_nonexistent_returns_not_found() {
    let kc = MockKeychainAdapter::new();
    let err = kc.retrieve(SVC, "absent").await.unwrap_err();
    assert!(matches!(err, KeychainError::NotFound));
}

// ── store is idempotent in the index ─────────────────────────────────────────

#[tokio::test]
async fn store_same_account_twice_not_duplicated_in_index() {
    let kc = MockKeychainAdapter::new();
    kc.store(SVC, "master-v1", b"v1").await.unwrap();
    kc.store(SVC, "master-v1", b"v1-updated").await.unwrap();

    let accounts = kc.list(SVC).await.unwrap();
    let count = accounts
        .iter()
        .filter(|a| a.as_str() == "master-v1")
        .count();
    assert_eq!(count, 1, "index must not contain duplicates");

    // Most-recent value must be returned.
    let got = kc.retrieve(SVC, "master-v1").await.unwrap();
    assert_eq!(got, b"v1-updated");
}

// ── index is per-service, not cross-service ───────────────────────────────────

#[tokio::test]
async fn index_is_scoped_per_service() {
    let kc = MockKeychainAdapter::new();
    kc.store("svc-a", "acct1", b"a").await.unwrap();
    kc.store("svc-b", "acct2", b"b").await.unwrap();

    let a_accounts = kc.list("svc-a").await.unwrap();
    let b_accounts = kc.list("svc-b").await.unwrap();
    assert_eq!(a_accounts, ["acct1"]);
    assert_eq!(b_accounts, ["acct2"]);
}

// ── overwrite updates stored value ────────────────────────────────────────────

#[tokio::test]
async fn overwrite_updates_value() {
    let kc = MockKeychainAdapter::new();
    kc.store(SVC, "key", b"original").await.unwrap();
    kc.store(SVC, "key", b"updated").await.unwrap();
    let got = kc.retrieve(SVC, "key").await.unwrap();
    assert_eq!(got, b"updated");
}
