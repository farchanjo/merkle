//! Integration tests for `SqliteStorage` using an in-memory SQLite database.

use merkle_adapter_sqlite::SqliteStorage;
use merkle_domain_access_mediation::companion_device::CompanionDevice;
use merkle_domain_audit_compliance::{AuditEntry, AuditQuery, PinnedHead};
use merkle_domain_backup_recovery::{
    artifact::BackupArtifact, backup::Backup, recipient::BackupRecipient, trigger::BackupTrigger,
};
use merkle_domain_policy_permissions::NamespacePolicy;
use merkle_domain_secret_storage::{
    Namespace, PublicMetadata, Secret,
    private_blob::PrivateBlob,
    secret_version::{SecretVersion, SecretVersionId},
};
use merkle_ports::{SecretFilter, Storage};
use merkle_types::{
    AuditEntryId, AuditOp, AuditOutcome, Blake3Hash, CategoryName, CompanionDeviceClass,
    Handle, HmacSignature, NamespaceId, NamespaceLabel, Rfc3339Timestamp, SecretId, SecretName,
    SecurityProfile, Sensitivity, UuidV7,
};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn open_memory() -> SqliteStorage {
    SqliteStorage::open("sqlite::memory:")
        .await
        .expect("in-memory DB should open")
}

fn label(s: &str) -> NamespaceLabel {
    s.parse().expect("valid label")
}

fn make_handle(ns: &str, cat: &str, name: &str) -> Handle {
    Handle::new(
        label(ns),
        cat.parse::<CategoryName>().expect("valid cat"),
        name.parse::<SecretName>().expect("valid name"),
    )
}

fn make_blob(handle: &Handle) -> PrivateBlob {
    let ad = handle.to_string().into_bytes();
    PrivateBlob::new(vec![0xAB; 32], [0u8; 24], [0u8; 16], ad, 1)
}

fn make_version(handle: &Handle, version_no: u32, secret_id: SecretId) -> SecretVersion {
    SecretVersion {
        id: SecretVersionId::new(),
        secret_id,
        version_no,
        blob: make_blob(handle),
        dek_version: 1,
        created_at: Rfc3339Timestamp::now(),
        deprecated_at: None,
    }
}

fn make_secret(ns_id: NamespaceId, handle: Handle) -> Secret {
    let v_id = SecretId::new();
    let v = make_version(&handle, 1, v_id);
    Secret::new(
        ns_id,
        handle,
        CategoryName::SshKey,
        Sensitivity::Medium,
        vec![],
        PublicMetadata::default(),
        v,
    )
    .expect("valid secret")
}

fn make_namespace(lbl: &str) -> Namespace {
    Namespace::new(label(lbl), 1)
}

fn dummy_hmac() -> HmacSignature {
    HmacSignature::compute(&[0u8; 32], b"test")
}

fn make_audit_entry(
    seq: u64,
    ns_id: NamespaceId,
    prev_hash: Option<Blake3Hash>,
) -> AuditEntry {
    use merkle_types::hash::GENESIS;
    let ph = prev_hash.unwrap_or(GENESIS);

    // Build minimal canonical bytes for hashing.
    let id = AuditEntryId::new();
    let ts = Rfc3339Timestamp::now();
    let op = AuditOp::Get;
    let outcome = AuditOutcome::Allow;

    // Compute current_hash from entry fields.
    let mut content = format!(
        r#"{{"id":"{id}","namespace_id":"{ns_id}","op":"{op}","outcome":"{outcome}","seq":{seq},"ts":"{ts}"}}"#
    )
    .into_bytes();
    content.extend_from_slice(ph.as_bytes());
    let current_hash = Blake3Hash::hash(&content);
    let hmac = dummy_hmac();

    AuditEntry {
        id,
        seq,
        ts,
        namespace_id: ns_id,
        caller_program: Some("test".to_owned()),
        op,
        outcome,
        denial_reason: None,
        handle: None,
        sensitivity: None,
        prev_hash: if seq == 0 { None } else { Some(ph) },
        current_hash,
        hmac: Some(hmac),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn round_trip_put_and_get_secret_by_handle() {
    let db = open_memory().await;

    let ns = make_namespace("my-project");
    db.put_namespace(&ns).await.expect("put_namespace");

    let handle = make_handle("my-project", "ssh", "my-key");
    let secret = make_secret(ns.id, handle.clone());

    db.put_secret(&secret).await.expect("put_secret");

    let fetched = db
        .get_secret_by_handle(&handle)
        .await
        .expect("get_secret_by_handle")
        .expect("secret must be present");

    assert_eq!(fetched.id, secret.id);
    assert_eq!(fetched.handle, secret.handle);
    assert_eq!(fetched.category, secret.category);
    assert_eq!(fetched.sensitivity, secret.sensitivity);
    assert_eq!(fetched.versions().len(), 1);
}

#[tokio::test]
async fn get_secret_by_handle_returns_none_when_missing() {
    let db = open_memory().await;
    let handle = make_handle("ghost-ns", "ssh", "nonexistent");
    let result = db
        .get_secret_by_handle(&handle)
        .await
        .expect("no DB error");
    assert!(result.is_none());
}

#[tokio::test]
async fn list_secrets_returns_all_in_namespace() {
    let db = open_memory().await;

    let ns = make_namespace("list-ns");
    db.put_namespace(&ns).await.expect("put_namespace");

    for i in 0..3u32 {
        let handle = make_handle("list-ns", "ssh", &format!("key-{i}"));
        let secret = make_secret(ns.id, handle);
        db.put_secret(&secret).await.expect("put_secret");
    }

    let secrets = db
        .list_secrets(&ns.id, SecretFilter::default())
        .await
        .expect("list_secrets");

    assert_eq!(secrets.len(), 3);
}

#[tokio::test]
async fn list_secrets_with_limit_filter() {
    let db = open_memory().await;

    let ns = make_namespace("limit-ns");
    db.put_namespace(&ns).await.expect("put_namespace");

    for i in 0..5u32 {
        let handle = make_handle("limit-ns", "ssh", &format!("key-{i}"));
        let secret = make_secret(ns.id, handle);
        db.put_secret(&secret).await.expect("put_secret");
    }

    let filter = SecretFilter {
        limit: Some(2),
        ..SecretFilter::default()
    };
    let secrets = db
        .list_secrets(&ns.id, filter)
        .await
        .expect("list_secrets with limit");

    assert_eq!(secrets.len(), 2);
}

#[tokio::test]
async fn delete_secret_removes_it() {
    let db = open_memory().await;

    let ns = make_namespace("del-ns");
    db.put_namespace(&ns).await.expect("put_namespace");

    let handle = make_handle("del-ns", "ssh", "to-delete");
    let secret = make_secret(ns.id, handle.clone());
    let secret_id = secret.id;
    db.put_secret(&secret).await.expect("put_secret");

    db.delete_secret(&secret_id).await.expect("delete_secret");

    let result = db
        .get_secret_by_handle(&handle)
        .await
        .expect("no DB error");
    assert!(result.is_none(), "secret must be gone after delete");
}

#[tokio::test]
async fn append_audit_entry_preserves_seq_and_chain() {
    let db = open_memory().await;
    let ns_id = NamespaceId::new();

    let entry0 = make_audit_entry(0, ns_id, None);
    let hash0 = entry0.current_hash;

    db.append_audit_entry(&entry0).await.expect("append entry 0");

    let entry1 = make_audit_entry(1, ns_id, Some(hash0));
    db.append_audit_entry(&entry1).await.expect("append entry 1");

    let q = AuditQuery::default();
    let entries = db.read_audit(&q).await.expect("read_audit");

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].seq, 0);
    assert_eq!(entries[1].seq, 1);
    assert_eq!(entries[1].prev_hash, Some(hash0));
}

#[tokio::test]
async fn pinned_head_updated_after_append() {
    let db = open_memory().await;

    // No head initially.
    let head = db.pinned_head().await.expect("pinned_head");
    assert!(head.is_none(), "empty DB has no pinned head");

    let ns_id = NamespaceId::new();
    let entry = make_audit_entry(0, ns_id, None);
    let current_hash = entry.current_hash;

    db.append_audit_entry(&entry).await.expect("append");

    let head = db
        .pinned_head()
        .await
        .expect("pinned_head")
        .expect("head must be present after append");

    assert_eq!(head.head_hash, current_hash);
    assert_eq!(head.head_seq, 0);
}

#[tokio::test]
async fn update_pinned_head_overwrites() {
    let db = open_memory().await;
    let ns_id = NamespaceId::new();

    let entry0 = make_audit_entry(0, ns_id, None);
    db.append_audit_entry(&entry0).await.expect("append");

    let new_head = PinnedHead::new(
        Blake3Hash::hash(b"synthetic"),
        999,
        AuditEntryId::new(),
        Rfc3339Timestamp::now(),
    );
    db.update_pinned_head(&new_head).await.expect("update_pinned_head");

    let fetched = db
        .pinned_head()
        .await
        .expect("pinned_head")
        .expect("must exist");

    assert_eq!(fetched.head_seq, 999);
    assert_eq!(fetched.head_hash, Blake3Hash::hash(b"synthetic"));
}

#[tokio::test]
async fn namespace_policy_round_trip() {
    let db = open_memory().await;

    let ns = make_namespace("policy-ns");
    db.put_namespace(&ns).await.expect("put_namespace");

    let mut policy = NamespacePolicy::defaults_for(SecurityProfile::Balanced);
    policy.namespace_id = ns.id;

    db.put_namespace_policy(&policy).await.expect("put_namespace_policy");

    let fetched = db
        .get_namespace_policy(&ns.id)
        .await
        .expect("get_namespace_policy")
        .expect("policy must be present");

    assert_eq!(fetched.id, policy.id);
    assert_eq!(fetched.namespace_id, ns.id);
}

#[tokio::test]
async fn get_namespace_policy_returns_none_when_absent() {
    let db = open_memory().await;
    let ns_id = NamespaceId::new();
    let result = db
        .get_namespace_policy(&ns_id)
        .await
        .expect("no DB error");
    assert!(result.is_none());
}

#[tokio::test]
async fn companion_device_round_trip() {
    let db = open_memory().await;

    let device = CompanionDevice {
        device_id: UuidV7::new(),
        ed25519_pubkey: [0u8; 32],
        x25519_pubkey: [1u8; 32],
        class: CompanionDeviceClass::SecureEnclave,
        attestation_chain: vec![0xDE, 0xAD, 0xBE, 0xEF],
        enrolled_at: Rfc3339Timestamp::now(),
        revoked_at: None,
    };

    db.put_companion_device(&device)
        .await
        .expect("put_companion_device");

    let devices = db
        .list_companion_devices()
        .await
        .expect("list_companion_devices");

    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, device.device_id);
    assert_eq!(devices[0].class, CompanionDeviceClass::SecureEnclave);
    assert_eq!(devices[0].attestation_chain, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[tokio::test]
async fn list_companion_devices_returns_all() {
    let db = open_memory().await;

    for i in 0..3u8 {
        let device = CompanionDevice {
            device_id: UuidV7::new(),
            ed25519_pubkey: [i; 32],
            x25519_pubkey: [i + 10; 32],
            class: CompanionDeviceClass::Software,
            attestation_chain: vec![],
            enrolled_at: Rfc3339Timestamp::now(),
            revoked_at: None,
        };
        db.put_companion_device(&device)
            .await
            .expect("put_companion_device");
    }

    let devices = db
        .list_companion_devices()
        .await
        .expect("list_companion_devices");

    assert_eq!(devices.len(), 3);
}

#[tokio::test]
async fn backup_round_trip() {
    let db = open_memory().await;

    let ns = make_namespace("backup-ns");
    db.put_namespace(&ns).await.expect("put_namespace");

    let hmac = dummy_hmac();
    let artifact = BackupArtifact::new(
        PathBuf::from("/tmp/merkle-bk-test.merkle.age"),
        1,
        hmac,
    );
    let backup = Backup::new(
        ns.id,
        UuidV7::new(),
        BackupTrigger::Manual,
        [BackupRecipient::MasterPubkey, BackupRecipient::RecoveryPublicKey],
        artifact,
        hmac,
        1024,
        5,
        Rfc3339Timestamp::now(),
    )
    .expect("valid backup");

    db.put_backup(&backup).await.expect("put_backup");

    let backups = db.list_backups(&ns.id).await.expect("list_backups");
    assert_eq!(backups.len(), 1);
    assert_eq!(backups[0].id, backup.id);
    assert_eq!(backups[0].secret_count, 5);
}
