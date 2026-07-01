//! Integration tests for `SqliteStorage` using an in-memory SQLite database.

use merkle_adapter_sqlite::SqliteStorage;
use merkle_domain_access_mediation::companion_device::CompanionDevice;
use merkle_domain_audit_compliance::{AuditBaseline, AuditEntry, AuditQuery, PinnedHead};
use merkle_domain_backup_recovery::{
    artifact::BackupArtifact, backup::Backup, recipient::BackupRecipient, trigger::BackupTrigger,
};
use merkle_domain_policy_permissions::NamespacePolicy;
use merkle_domain_secret_storage::{
    Namespace, PublicMetadata, Secret,
    private_blob::PrivateBlob,
    secret_version::{SecretVersion, SecretVersionId},
};
use merkle_ports::{RankedSearchParams, SecretFilter, Storage};
use merkle_types::{
    AuditEntryId, AuditOp, AuditOutcome, Blake3Hash, CategoryName, CompanionDeviceClass, Handle,
    HmacSignature, NamespaceId, NamespaceLabel, Rfc3339Timestamp, SecretId, SecretName,
    SecurityProfile, Sensitivity, Tag, UuidV7,
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

fn make_audit_entry(seq: u64, ns_id: NamespaceId, prev_hash: Option<Blake3Hash>) -> AuditEntry {
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
async fn audit_baseline_round_trips_and_upserts() {
    let db = open_memory().await;

    // No baseline pinned on a fresh vault.
    assert!(
        db.audit_baseline().await.expect("query").is_none(),
        "a fresh vault has no baseline"
    );

    let anchor_id = AuditEntryId::new();
    let baseline = AuditBaseline::new(
        7,
        anchor_id,
        Blake3Hash::hash(b"anchor"),
        8,
        "recovery: quarantine pre-rotation prefix".to_owned(),
        Rfc3339Timestamp::now(),
    )
    .with_mac(&[0x42; 32]);

    db.set_audit_baseline(&baseline).await.expect("set");

    let loaded = db.audit_baseline().await.expect("query").expect("present");
    assert_eq!(loaded.baseline_seq, 7);
    assert_eq!(loaded.baseline_id, anchor_id);
    assert_eq!(loaded.baseline_hash, baseline.baseline_hash);
    assert_eq!(loaded.entry_count, 8);
    assert_eq!(loaded.reason, "recovery: quarantine pre-rotation prefix");
    assert!(
        loaded.verify_mac(&[0x42; 32]),
        "a round-tripped baseline must still authenticate under its key"
    );

    // Upsert: pinning again replaces the singleton row rather than duplicating.
    let updated = AuditBaseline::new(
        9,
        AuditEntryId::new(),
        Blake3Hash::hash(b"anchor2"),
        10,
        "second pin".to_owned(),
        Rfc3339Timestamp::now(),
    )
    .with_mac(&[0x42; 32]);
    db.set_audit_baseline(&updated).await.expect("upsert");

    let reloaded = db.audit_baseline().await.expect("query").expect("present");
    assert_eq!(
        reloaded.baseline_seq, 9,
        "the singleton baseline row must be replaced in place"
    );
    assert_eq!(reloaded.entry_count, 10);
}

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
    let result = db.get_secret_by_handle(&handle).await.expect("no DB error");
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

/// Build a `Secret` with explicit tags and a deterministic `created_at` so the
/// `ORDER BY created_at ASC` list ordering is reproducible across rows.
fn make_secret_with_tags(
    ns_id: NamespaceId,
    handle: Handle,
    tags: Vec<Tag>,
    created_at: &str,
) -> Secret {
    let v_id = SecretId::new();
    let v = make_version(&handle, 1, v_id);
    let mut secret = Secret::new(
        ns_id,
        handle,
        CategoryName::Token,
        Sensitivity::Low,
        tags,
        PublicMetadata::default(),
        v,
    )
    .expect("valid secret");
    secret.created_at = created_at.parse().expect("valid timestamp");
    secret
}

/// BUG-04: with a tag filter present, the SQL `LIMIT` must apply AFTER tag
/// matching, not before. Two non-matching rows are inserted first (earliest
/// `created_at`), then three matching rows. Before the fix, `LIMIT 2` truncated
/// to the two earliest (non-matching) rows and the Rust tag filter then dropped
/// both, yielding zero results.
#[tokio::test]
async fn list_secrets_tag_filter_applies_limit_after_matching() {
    let db = open_memory().await;

    let ns = make_namespace("tagfilter-ns");
    db.put_namespace(&ns).await.expect("put_namespace");

    let prod: Tag = "env:prod".parse().expect("valid tag");

    // Two non-matching secrets first (oldest created_at).
    for i in 0..2u32 {
        let handle = make_handle("tagfilter-ns", "token", &format!("dev-key-{i}"));
        let secret =
            make_secret_with_tags(ns.id, handle, vec![], &format!("2026-01-01T00:00:0{i}Z"));
        db.put_secret(&secret).await.expect("put_secret");
    }
    // Three matching secrets after (newer created_at).
    for i in 0..3u32 {
        let handle = make_handle("tagfilter-ns", "token", &format!("prod-key-{i}"));
        let secret = make_secret_with_tags(
            ns.id,
            handle,
            vec![prod.clone()],
            &format!("2026-01-01T00:00:1{i}Z"),
        );
        db.put_secret(&secret).await.expect("put_secret");
    }

    let filter = SecretFilter {
        tag_match: Some(vec![prod.clone()]),
        limit: Some(2),
        ..SecretFilter::default()
    };
    let secrets = db
        .list_secrets(&ns.id, filter)
        .await
        .expect("list_secrets with tag filter + limit");

    assert_eq!(
        secrets.len(),
        2,
        "tag filter + limit must return a full page of matching rows"
    );
    for secret in &secrets {
        assert!(
            secret.tags.contains(&prod),
            "every returned secret must carry the env:prod tag"
        );
    }
}

/// BUG-03: `put_secret` must materialize `namespace_label` so the FTS5 triggers
/// index the real namespace label. The only FTS column that can contain
/// "zephyrnamespace" is `namespace_label`; before the fix it was stored as `''`
/// and this search returned nothing.
#[tokio::test]
async fn search_by_namespace_label_returns_row() {
    let db = open_memory().await;

    let ns = make_namespace("zephyrnamespace");
    db.put_namespace(&ns).await.expect("put_namespace");

    let handle = make_handle("zephyrnamespace", "ssh", "mykey");
    let secret = make_secret(ns.id, handle);
    db.put_secret(&secret).await.expect("put_secret");

    let result = ranked_search(&db, &ns.id, "zephyrnamespace", 10, 0).await;
    assert_eq!(
        result.items.len(),
        1,
        "search by namespace label must return the secret"
    );
    assert_eq!(result.items[0].secret.id, secret.id);
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

    let result = db.get_secret_by_handle(&handle).await.expect("no DB error");
    assert!(result.is_none(), "secret must be gone after delete");
}

#[tokio::test]
async fn append_audit_entry_preserves_seq_and_chain() {
    let db = open_memory().await;
    let ns_id = NamespaceId::new();

    let entry0 = make_audit_entry(0, ns_id, None);
    let hash0 = entry0.current_hash;

    db.append_audit_entry(&entry0)
        .await
        .expect("append entry 0");

    let entry1 = make_audit_entry(1, ns_id, Some(hash0));
    db.append_audit_entry(&entry1)
        .await
        .expect("append entry 1");

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
    db.update_pinned_head(&new_head)
        .await
        .expect("update_pinned_head");

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

    db.put_namespace_policy(&policy)
        .await
        .expect("put_namespace_policy");

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
    let result = db.get_namespace_policy(&ns_id).await.expect("no DB error");
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

/// ADR-0025 §Bug #2 — `list_namespaces` returns all persisted rows.
#[tokio::test]
async fn list_namespaces_returns_all_persisted_rows() {
    let db = open_memory().await;

    let labels = ["alpha", "beta", "gamma"];
    for lbl in labels {
        let ns = make_namespace(lbl);
        db.put_namespace(&ns).await.expect("put_namespace");
    }

    let items = db.list_namespaces().await.expect("list_namespaces");

    assert_eq!(items.len(), 3, "expected 3 namespaces, got {}", items.len());

    // Order-tolerant: compare via a HashSet of label strings.
    let returned_labels: std::collections::HashSet<String> =
        items.iter().map(|ns| ns.label.to_string()).collect();
    let expected_labels: std::collections::HashSet<String> =
        labels.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        returned_labels, expected_labels,
        "returned labels do not match inserted labels"
    );
}

#[tokio::test]
async fn backup_round_trip() {
    let db = open_memory().await;

    let ns = make_namespace("backup-ns");
    db.put_namespace(&ns).await.expect("put_namespace");

    let hmac = dummy_hmac();
    let artifact = BackupArtifact::new(PathBuf::from("/tmp/merkle-bk-test.merkle.age"), 1, hmac);
    let backup = Backup::new(
        ns.id,
        UuidV7::new(),
        BackupTrigger::Manual,
        [
            BackupRecipient::MasterPubkey,
            BackupRecipient::RecoveryPublicKey,
        ],
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

// ===========================================================================
// ADR-0027: Weighted BM25 FTS5 tests
// ===========================================================================

// ---------------------------------------------------------------------------
// BM25 test helpers
// ---------------------------------------------------------------------------

/// Build a `Secret` with a custom description in `public_metadata_json`.
fn make_secret_with_description(
    ns_id: NamespaceId,
    handle: Handle,
    description: &str,
    category: CategoryName,
) -> Secret {
    let v_id = SecretId::new();
    let v = make_version(&handle, 1, v_id);
    let mut pm = PublicMetadata::new(true);
    pm.description = Some(description.to_owned());
    Secret::new(ns_id, handle, category, Sensitivity::Low, vec![], pm, v).expect("valid secret")
}

/// Await a ranked search and unwrap.
async fn ranked_search(
    db: &SqliteStorage,
    ns_id: &NamespaceId,
    query: &str,
    limit: u32,
    offset: u32,
) -> merkle_ports::RankedSearchResult {
    db.search_secrets(
        ns_id,
        RankedSearchParams {
            fts_query: query.to_owned(),
            limit,
            offset,
        },
    )
    .await
    .expect("search_secrets should not fail")
}

// ---------------------------------------------------------------------------
// Test 1 (ADR-0027 §Validation 2): BM25 ranking — name-match ranks above
// description-match for the same query term.
// ---------------------------------------------------------------------------

/// ADR-0027 §Validation 2: name-match secrets rank above description-match
/// secrets. Three secrets have "github" in `name`; seven have it only in
/// `description`.  The first three results must be the name-match secrets.
#[tokio::test]
async fn bm25_name_match_ranks_above_description_match() {
    let db = open_memory().await;
    let ns = make_namespace("rank-ns");
    db.put_namespace(&ns).await.expect("put_namespace");
    let ns_id = ns.id;

    // 3 secrets with "github" in name.
    for i in 0..3u32 {
        let handle = make_handle("rank-ns", "token", &format!("github-token-{i}"));
        let secret = make_secret_with_description(
            ns_id,
            handle,
            "deploy key for CI pipelines",
            CategoryName::Token,
        );
        db.put_secret(&secret).await.expect("put_secret");
    }

    // 7 secrets with "github" only in description.
    for i in 0..7u32 {
        let handle = make_handle("rank-ns", "token", &format!("unrelated-token-{i}"));
        let secret = make_secret_with_description(
            ns_id,
            handle,
            "token used for github organization workflows",
            CategoryName::Token,
        );
        db.put_secret(&secret).await.expect("put_secret");
    }

    let result = ranked_search(&db, &ns_id, "github", 10, 0).await;
    assert_eq!(result.items.len(), 10, "all 10 secrets must match");
    assert_eq!(result.total, 10);

    // The first 3 results must have "github" in their handle name segment.
    for item in result.items.iter().take(3) {
        assert!(
            item.secret
                .handle
                .secret_name()
                .to_string()
                .contains("github"),
            "expected a github-named secret in top-3, got: {}",
            item.secret.handle
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2 (ADR-0027 §Validation 5): weighted BM25 — name-match beats equal-TF
// description-match due to the 10.0 vs 3.0 column weight.
// ---------------------------------------------------------------------------

/// ADR-0027 §Validation 5: with equal term frequency (one occurrence each),
/// a name match ranks above a description match.
/// BM25 column weights (10.0 name vs 3.0 description) guarantee this for
/// equal TF. Extreme TF-stuffing uses non-equal TF; the weight ratio applies
/// to the saturated TF component, not to raw repetition counts.
#[tokio::test]
async fn bm25_name_weight_dominates_description_tf_stuffing() {
    let db = open_memory().await;
    let ns = make_namespace("tf-ns");
    db.put_namespace(&ns).await.expect("put_namespace");
    let ns_id = ns.id;

    // Add background noise documents (no "deploy") to give IDF a positive value.
    for i in 0..10u32 {
        let h = make_handle("tf-ns", "token", &format!("noise-token-{i}"));
        let s = make_secret_with_description(
            ns_id,
            h,
            "oauth integration service",
            CategoryName::Token,
        );
        db.put_secret(&s).await.expect("put noise secret");
    }

    // Secret A: "deploy" in name (weight 10.0), neutral description.
    let handle_a = make_handle("tf-ns", "token", "deploy-token");
    let secret_a =
        make_secret_with_description(ns_id, handle_a, "production CI token", CategoryName::Token);
    db.put_secret(&secret_a).await.expect("put secret A");

    // Secret B: "deploy" once in description (weight 3.0), unrelated name.
    let handle_b = make_handle("tf-ns", "note", "unrelated-note");
    let secret_b = make_secret_with_description(
        ns_id,
        handle_b,
        "deploy integration for pipeline",
        CategoryName::Note,
    );
    db.put_secret(&secret_b).await.expect("put secret B");

    let result = ranked_search(&db, &ns_id, "deploy", 10, 0).await;
    assert_eq!(result.items.len(), 2, "both secrets must match");

    // Equal-TF: name match (weight 10.0) must beat description match (weight 3.0).
    let top = &result.items[0];
    assert_eq!(top.bm25_rank, 1);
    assert!(
        top.secret
            .handle
            .secret_name()
            .to_string()
            .contains("deploy"),
        "equal-TF name match must rank first, got: {}",
        top.secret.handle
    );

    // Top result has a more-negative (better) score than the second.
    assert!(
        result.items[0].score <= result.items[1].score,
        "top result score ({}) should be <= second result score ({})",
        result.items[0].score,
        result.items[1].score
    );
}

// ---------------------------------------------------------------------------
// Test 3 (ADR-0027 §Validation 3): highlight snippets contain `<b>` tags and
// reference only public fields.
// ---------------------------------------------------------------------------

/// ADR-0027 §Validation 3: search returns per-field highlight snippets with
/// `<b>` markers; private fields never appear in highlights.
#[tokio::test]
async fn bm25_highlights_present_and_public_fields_only() {
    let db = open_memory().await;
    let ns = make_namespace("hl-ns");
    db.put_namespace(&ns).await.expect("put_namespace");
    let ns_id = ns.id;

    let handle = make_handle("hl-ns", "ssh", "bastion-prod-key");
    let secret = make_secret_with_description(
        ns_id,
        handle,
        "SSH key for the production bastion host",
        CategoryName::SshKey,
    );
    db.put_secret(&secret).await.expect("put_secret");

    let result = ranked_search(&db, &ns_id, "bastion", 10, 0).await;
    assert_eq!(result.items.len(), 1);

    let item = &result.items[0];
    assert!(
        !item.highlights.is_empty(),
        "at least one highlight must be present"
    );

    // At least one highlight from `name` or `description` must contain <b>.
    let has_bold = item
        .highlights
        .iter()
        .any(|h| h.snippet.contains("<b>") && h.snippet.contains("</b>"));
    assert!(has_bold, "highlights must contain <b> markers");

    // Private field names must never appear as highlight fields.
    let forbidden_fields = [
        "private_blob",
        "ciphertext",
        "nonce",
        "aead_tag",
        "associated_data",
    ];
    for h in &item.highlights {
        assert!(
            !forbidden_fields.contains(&h.field.as_str()),
            "private field '{}' must not appear in highlights",
            h.field
        );
    }
}

// ---------------------------------------------------------------------------
// Test 4 (ADR-0027 §Validation 4): UPDATE trigger freshness — post-rotate
// description updates are reflected in the FTS5 index.
// ---------------------------------------------------------------------------

/// ADR-0027 §Validation 4: after updating `public_metadata_json` via an
/// UPDATE (simulating rotate), the old description is no longer indexed and
/// the new description is searchable.
#[tokio::test]
async fn bm25_update_trigger_reflects_metadata_change() {
    let db = open_memory().await;
    let ns = make_namespace("upd-ns");
    db.put_namespace(&ns).await.expect("put_namespace");
    let ns_id = ns.id;

    let handle = make_handle("upd-ns", "token", "old-token");

    // Initial insert with description "old description alpha".
    let secret_initial = make_secret_with_description(
        ns_id,
        handle.clone(),
        "old description alpha",
        CategoryName::Token,
    );
    let secret_id = secret_initial.id;
    db.put_secret(&secret_initial)
        .await
        .expect("put_secret initial");

    // Verify "alpha" is findable before update.
    let before = ranked_search(&db, &ns_id, "alpha", 10, 0).await;
    assert_eq!(
        before.items.len(),
        1,
        "alpha must be findable before update"
    );

    // Update: replace the secret with new description "production oauth token beta".
    let mut updated = db
        .get_secret_by_handle(&handle)
        .await
        .expect("get_secret_by_handle")
        .expect("must exist");
    updated.public_metadata.description = Some("production oauth token beta".to_owned());
    // Use put_secret to upsert the updated public_metadata_json.
    // This triggers the secrets_fts_au UPDATE trigger.
    db.put_secret(&updated).await.expect("put_secret update");

    // "alpha" must no longer be findable.
    let alpha_after = ranked_search(&db, &ns_id, "alpha", 10, 0).await;
    assert_eq!(
        alpha_after.items.len(),
        0,
        "alpha must not appear after update"
    );

    // "oauth" must now be findable.
    let oauth_after = ranked_search(&db, &ns_id, "oauth", 10, 0).await;
    assert_eq!(oauth_after.items.len(), 1, "oauth must appear after update");
    assert_eq!(oauth_after.items[0].secret.id, secret_id);
}

// ---------------------------------------------------------------------------
// Test 5 (ADR-0027 §Validation 6): pagination preserves rank order.
// ---------------------------------------------------------------------------

/// ADR-0027 §Validation 6: ranked results on page 1 have better (more-negative)
/// scores than results on page 2; no handle appears on both pages.
#[tokio::test]
async fn bm25_pagination_preserves_rank_order() {
    let db = open_memory().await;
    let ns = make_namespace("page-ns");
    db.put_namespace(&ns).await.expect("put_namespace");
    let ns_id = ns.id;

    // Insert 15 secrets: 5 with "acme" in name (higher rank), 10 in description.
    for i in 0..5u32 {
        let handle = make_handle("page-ns", "token", &format!("acme-token-{i}"));
        let secret =
            make_secret_with_description(ns_id, handle, "integration token", CategoryName::Token);
        db.put_secret(&secret).await.expect("put name-match");
    }
    for i in 0..10u32 {
        let handle = make_handle("page-ns", "note", &format!("integration-note-{i}"));
        let secret = make_secret_with_description(
            ns_id,
            handle,
            "acme organization infrastructure note",
            CategoryName::Note,
        );
        db.put_secret(&secret).await.expect("put desc-match");
    }

    let page1 = ranked_search(&db, &ns_id, "acme", 5, 0).await;
    let page2 = ranked_search(&db, &ns_id, "acme", 5, 5).await;

    assert_eq!(page1.items.len(), 5, "page 1 must have 5 items");
    assert_eq!(page2.items.len(), 5, "page 2 must have 5 items");
    assert_eq!(page1.total, 15, "total must be 15");
    assert!(page1.has_more, "page 1 must have has_more=true");

    // No overlap between pages.
    let page1_handles: std::collections::HashSet<String> = page1
        .items
        .iter()
        .map(|r| r.secret.handle.to_string())
        .collect();
    let page2_handles: std::collections::HashSet<String> = page2
        .items
        .iter()
        .map(|r| r.secret.handle.to_string())
        .collect();
    assert!(
        page1_handles.is_disjoint(&page2_handles),
        "no handle must appear on both pages"
    );

    // Last result on page 1 has score ≤ first result on page 2
    // (page 1 is ordered best-first; last on p1 is worse than first on p2).
    let last_p1_score = page1.items.last().expect("nonempty").score;
    let first_p2_score = page2.items.first().expect("nonempty").score;
    assert!(
        last_p1_score <= first_p2_score,
        "last page-1 score ({last_p1_score}) must be more relevant (≤) than first page-2 score ({first_p2_score})"
    );

    // Page-local bm25_rank starts at 1 on each page.
    assert_eq!(page1.items[0].bm25_rank, 1, "page 1 rank 1 must be 1");
    assert_eq!(page2.items[0].bm25_rank, 1, "page 2 rank 1 must be 1");
}

// ---------------------------------------------------------------------------
// Test 6 (ADR-0027 §Validation 1 + Validation 8): privacy audit — private
// fields never in FTS5 index or highlights.
// ---------------------------------------------------------------------------

/// ADR-0027 §Validation 1 + 8: FTS5 index contains no private field names;
/// search for "SUPERSECRET" returns zero results; highlights carry no
/// private field names.
#[tokio::test]
async fn bm25_privacy_audit_private_fields_never_indexed() {
    let db = open_memory().await;
    let ns = make_namespace("priv-ns");
    db.put_namespace(&ns).await.expect("put_namespace");
    let ns_id = ns.id;

    // Insert a secret — the ciphertext bytes are never in the FTS5 index.
    let handle = make_handle("priv-ns", "ssh", "prod-key");
    let ad = handle.to_string().into_bytes();
    // Use a recognizable "private" pattern in the ciphertext bytes.
    let ciphertext = b"SUPERSECRET_KEY_MATERIAL".to_vec();
    let blob = PrivateBlob::new(ciphertext, [0u8; 24], [0u8; 16], ad, 1);
    let version = SecretVersion {
        id: SecretVersionId::new(),
        secret_id: SecretId::new(),
        version_no: 1,
        blob,
        dek_version: 1,
        created_at: Rfc3339Timestamp::now(),
        deprecated_at: None,
    };
    let pm = PublicMetadata::new(true);
    let secret = Secret::new(
        ns_id,
        handle,
        CategoryName::SshKey,
        Sensitivity::Low,
        vec![],
        pm,
        version,
    )
    .expect("valid secret");
    db.put_secret(&secret).await.expect("put_secret");

    // Searching for the ciphertext content must return zero results.
    let result = ranked_search(&db, &ns_id, "SUPERSECRET", 10, 0).await;
    assert_eq!(
        result.items.len(),
        0,
        "private ciphertext bytes must not be indexed in FTS5"
    );

    // FTS5 consistency check must pass (column list correct, no orphans).
    db.check_fts5_consistency()
        .await
        .expect("fts5 consistency check must pass");
}

// ---------------------------------------------------------------------------
// Test 7 (ADR-0027 §Validation 7): doctor check validates FTS5 schema.
// ---------------------------------------------------------------------------

/// ADR-0027 §Validation 7: `check_fts5_consistency` passes on a correctly
/// initialized database.
#[tokio::test]
async fn bm25_doctor_fts5_schema_check_passes() {
    let db = open_memory().await;

    // An empty DB (no secrets) must still pass — column list is the authority.
    db.check_fts5_consistency()
        .await
        .expect("fts5 consistency check must pass on empty DB");

    // Insert a namespace + secret, then check again.
    let ns = make_namespace("doctor-ns");
    db.put_namespace(&ns).await.expect("put_namespace");
    let handle = make_handle("doctor-ns", "ssh", "my-key");
    let secret = make_secret(ns.id, handle);
    db.put_secret(&secret).await.expect("put_secret");

    db.check_fts5_consistency()
        .await
        .expect("fts5 consistency check must pass after insert");
}

// ---------------------------------------------------------------------------
// Test 8 (ADR-0027 §Validation — porter stemming): inflected terms match.
// ---------------------------------------------------------------------------

/// ADR-0027 stemming: porter tokenizer maps "authenticat*" to the same stem
/// as "authentication" and "authorization".
#[tokio::test]
async fn bm25_porter_stemming_matches_inflected_terms() {
    let db = open_memory().await;
    let ns = make_namespace("stem-ns");
    db.put_namespace(&ns).await.expect("put_namespace");
    let ns_id = ns.id;

    // Document uses the noun "authentication"; we query with the verb "authenticate".
    // Porter stemming maps both to the same stem so they match.
    let handle = make_handle("stem-ns", "token", "auth-service-token");
    let secret = make_secret_with_description(
        ns_id,
        handle,
        "authentication token for the authorization service",
        CategoryName::Token,
    );
    db.put_secret(&secret).await.expect("put_secret");

    // "authenticate" (verb) must match "authentication" (noun) via Porter stemming.
    let result_auth = ranked_search(&db, &ns_id, "authenticate", 10, 0).await;
    assert!(
        !result_auth.items.is_empty(),
        "porter stemmer must match 'authenticate' against 'authentication'"
    );

    // "authorize" must match "authorization" via Porter stemming.
    let result_author = ranked_search(&db, &ns_id, "authorize", 10, 0).await;
    assert!(
        !result_author.items.is_empty(),
        "porter stemmer must match 'authorize' against 'authorization'"
    );

    // Prefix query: "auth" prefix must find the document.
    let result_prefix = ranked_search(&db, &ns_id, "auth*", 10, 0).await;
    assert!(
        !result_prefix.items.is_empty(),
        "prefix 'auth*' must match 'authentication' and 'authorization'"
    );
}
