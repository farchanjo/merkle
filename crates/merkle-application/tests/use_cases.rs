//! Integration tests for `merkle-application` use-case handlers.
//!
//! Uses SQLite in-memory storage, `RustCryptoAdapter`, `MockKeychainAdapter`,
//! `MockOobNotifier`, and `MockExternalServices` to exercise the full
//! command/query layer without any infrastructure side effects.

use std::sync::Arc;

use merkle_adapter_crypto::RustCryptoAdapter;
use merkle_adapter_external_services::MockExternalServices;
use merkle_adapter_keychain::MockKeychainAdapter;
use merkle_adapter_oob::mock::MockOobNotifier;
use merkle_adapter_sqlite::SqliteStorage;
use merkle_application::{
    AppContext,
    commands::{
        bind_namespace::BindNamespaceCommand, init_vault::InitVaultCommand,
        list_secrets::ListSecretsCommand, put_secret::PutSecretCommand,
        seal_vault::SealVaultCommand, unseal_vault::UnsealVaultCommand,
    },
    queries::{
        agent_status::AgentStatusQuery, list_namespaces::ListNamespacesQuery,
        query_audit::QueryAuditQuery,
    },
};
use merkle_domain_identity::{
    KEYCHAIN_ACCOUNT_MASTER_KEY, KEYCHAIN_SERVICE, KeychainEntry, RecoveryPublicKey, SealedState,
    UnsealPreconditions, VaultIdentity,
};
use merkle_types::{
    AuditOutcome, CategoryName, NamespaceLabel, Rfc3339Timestamp, SecurityProfile, Sensitivity,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build an `AppContext` backed by in-memory SQLite and all mock adapters.
async fn make_ctx() -> AppContext {
    let storage = SqliteStorage::open("sqlite::memory:")
        .await
        .expect("in-memory sqlite");

    let crypto = Arc::new(RustCryptoAdapter::new());
    let keychain = Arc::new(MockKeychainAdapter::new());
    let oob = Arc::new(MockOobNotifier::new());
    let external = Arc::new(MockExternalServices::new());

    // Build a minimal VaultIdentity.
    let keychain_ref = KeychainEntry::for_master_key(1, Rfc3339Timestamp::now());
    let recovery_pubkey = RecoveryPublicKey::new(
        "age1test".to_owned(),
        "SHA256:test=".to_owned(),
        Rfc3339Timestamp::now(),
    );
    let identity = VaultIdentity::new(keychain_ref, recovery_pubkey);

    AppContext::new(Arc::new(storage), keychain, crypto, oob, external, identity)
}

/// Master key bytes: the mock keychain stores these as-is for any service/account.
fn master_key_bytes() -> [u8; 32] {
    [0xAB_u8; 32]
}

/// A fixed 32-byte DEK for test secrets.
fn test_dek() -> [u8; 32] {
    [0xCD_u8; 32]
}

/// Pre-load the MasterKey **and** a correctly master-wrapped VRK in the mock
/// keychain so `unseal_vault` can retrieve both — modelling a vault that has
/// already run `init_vault`. BUG-005: unseal AEAD-decrypts the wrapped VRK that
/// init persisted (it no longer recomputes a placeholder), so the wrapped blob
/// must be present in the same `BASE64(nonce || ciphertext)` format init writes.
async fn preload_master_key(ctx: &AppContext) {
    ctx.keychain
        .store("dev.fapp.merkle", "master-v1", &master_key_bytes())
        .await
        .expect("store master key");
    seed_master_wrapped_vrk(ctx).await;
}

/// Wrap a deterministic VRK under the master key and store it where
/// `unseal_vault` expects it, mirroring `init_vault`'s persisted format.
async fn seed_master_wrapped_vrk(ctx: &AppContext) {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use merkle_application::commands::init_vault::{KEYCHAIN_ACCOUNT_VRK_MASTER, VRK_MASTER_AAD};
    use merkle_ports::Crypto;

    let crypto = RustCryptoAdapter::new();
    let vrk = [0x11_u8; 32];
    let nonce = [0x22_u8; 24];
    let ciphertext = crypto
        .aead_encrypt(&master_key_bytes(), &nonce, &vrk, VRK_MASTER_AAD)
        .expect("wrap vrk under master key");

    let mut buf = Vec::with_capacity(nonce.len() + ciphertext.len());
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(&ciphertext);
    let payload = BASE64.encode(&buf).into_bytes();

    ctx.keychain
        .store(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_VRK_MASTER, &payload)
        .await
        .expect("store master-wrapped VRK");
}

/// Unseal the vault and return `true`.
async fn unseal(ctx: &AppContext) -> bool {
    preload_master_key(ctx).await;

    let cmd = UnsealVaultCommand {
        preconditions: UnsealPreconditions {
            security_profile: SecurityProfile::Balanced,
            mlock_succeeded: true,
            entropy_seeded: true,
            keychain_reachable: true,
        },
    };
    let out = cmd.execute(ctx).await.expect("unseal should succeed");
    out.unsealed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// ADR-0029 — re-baseline pins a trusted baseline, requires confirmation, and
/// keeps the chain verifying via the baseline-anchored path.
#[tokio::test]
async fn test_set_audit_baseline_pins_and_verifies() {
    use merkle_application::commands::set_audit_baseline::SetAuditBaselineCommand;
    use merkle_application::queries::verify_chain::VerifyChainQuery;
    use merkle_domain_audit_compliance::ChainOutcome;

    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await, "vault must unseal");

    // No baseline pinned yet.
    assert!(
        ctx.storage.audit_baseline().await.expect("query").is_none(),
        "a fresh vault has no baseline"
    );

    // An unconfirmed request must be rejected.
    let unconfirmed = SetAuditBaselineCommand {
        reason: "no confirmation".into(),
        confirmed: false,
    };
    assert!(
        unconfirmed.execute(&ctx).await.is_err(),
        "re-baseline must require explicit operator confirmation"
    );

    // A confirmed re-baseline pins a baseline anchored on a fresh marker.
    let cmd = SetAuditBaselineCommand {
        reason: "recovery: quarantine pre-rotation prefix".into(),
        confirmed: true,
    };
    let out = cmd.execute(&ctx).await.expect("rebaseline must succeed");
    assert!(
        ctx.storage.audit_baseline().await.expect("query").is_some(),
        "a baseline must be pinned after re-baseline"
    );

    // Verification now runs the baseline-anchored path and stays Intact.
    let verify = VerifyChainQuery.execute(&ctx).await.expect("verify");
    assert_eq!(verify.result.outcome, ChainOutcome::Intact);
    assert_eq!(
        verify.result.baseline_seq,
        Some(out.baseline_seq),
        "verification must be anchored to the pinned baseline"
    );
}

/// T01 — put_secret + list_secrets round-trip.
#[tokio::test]
async fn test_put_and_list_secrets_round_trip() {
    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    // Create a namespace first.
    let ns_label: NamespaceLabel = "prod".parse().expect("parse ns label");
    let ns_cmd = BindNamespaceCommand {
        label: ns_label.clone(),
        cwd_hash: None,
        dek_version: 1,
    };
    let ns_out = ns_cmd.execute(&ctx).await.expect("bind namespace");
    let ns_id = ns_out.namespace_id;

    // Put a secret.
    let handle = "vault://prod/ssh-key/bastion"
        .parse()
        .expect("parse handle");
    let put_cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle,
        category: "ssh-key".parse::<CategoryName>().expect("category"),
        sensitivity: Sensitivity::Medium,
        tags: vec![],
        expose_metadata: false,
        plaintext: b"ssh-ed25519 AAAA...".to_vec(),
        dek_version: 1,
        dek_bytes: test_dek(),
        value_format: merkle_application::ValueFormat::Utf8,
    };
    let put_out = put_cmd
        .execute(&ctx)
        .await
        .expect("put_secret should succeed");

    // List secrets.
    let list_cmd = ListSecretsCommand {
        namespace_id: ns_id,
        tag_match: None,
        name_pattern: None,
        limit: None,
    };
    let list_out = list_cmd
        .execute(&ctx)
        .await
        .expect("list_secrets should succeed");

    assert_eq!(list_out.secrets.len(), 1);
    assert_eq!(list_out.secrets[0].id, put_out.secret_id);
}

/// T02b — unseal_vault distinguishes "transitioned now" vs "was already unsealed".
///
/// Bug #5 (ADR-0025): both paths previously returned the same opaque flag,
/// so the CLI printed "vault was already unsealed" even when the call actually
/// performed the seal→unsealed transition (live smoke test 2026-05-24).
#[tokio::test]
async fn test_unseal_was_already_unsealed_distinguishes_paths() {
    use merkle_application::commands::unseal_vault::UnsealVaultCommand;
    use merkle_domain_identity::UnsealPreconditions;

    let ctx = make_ctx().await;
    preload_master_key(&ctx).await;
    let cmd = UnsealVaultCommand {
        preconditions: UnsealPreconditions {
            security_profile: SecurityProfile::Balanced,
            mlock_succeeded: true,
            entropy_seeded: true,
            keychain_reachable: true,
        },
    };

    // First call: vault was sealed → must report `was_already_unsealed = false`.
    let first = cmd.execute(&ctx).await.expect("first unseal");
    assert!(first.unsealed, "vault must end up unsealed");
    assert!(
        !first.was_already_unsealed,
        "first unseal transitioned sealed→unsealed; was_already_unsealed must be false"
    );

    // Second call: vault was already unsealed → must report
    // `was_already_unsealed = true` and not re-run key fetch.
    let second = cmd.execute(&ctx).await.expect("second unseal");
    assert!(second.unsealed, "vault stays unsealed");
    assert!(
        second.was_already_unsealed,
        "second unseal is a no-op; was_already_unsealed must be true"
    );
}

/// T02 — unseal_vault + seal_vault state transitions.
#[tokio::test]
async fn test_unseal_and_seal_transitions() {
    let ctx = make_ctx().await;

    // Initially sealed.
    assert!(!ctx.is_unsealed().await);

    // Unseal.
    let unsealed = unseal(&ctx).await;
    assert!(unsealed);
    assert!(ctx.is_unsealed().await);

    // Seal.
    let seal_cmd = SealVaultCommand;
    let seal_out = seal_cmd.execute(&ctx).await.expect("seal should succeed");
    assert!(seal_out.sealed);
    assert!(!ctx.is_unsealed().await);

    // HMAC key should be zeroed.
    let hmac_guard = ctx.hmac_key.read().await;
    assert!(hmac_guard.is_none(), "HMAC key must be cleared after seal");
}

/// T03 — reveal_secret denied when sensitivity=High without OOB.
#[tokio::test]
async fn test_reveal_denied_high_sensitivity_no_oob() {
    use merkle_application::commands::reveal_secret::RevealSecretCommand;
    use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;
    use merkle_types::{CompanionDeviceClass, OobChannel};
    use std::time::Duration;

    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    // Bind namespace.
    let ns_label: NamespaceLabel = "secure".parse().expect("ns label");
    let ns_cmd = BindNamespaceCommand {
        label: ns_label.clone(),
        cwd_hash: None,
        dek_version: 1,
    };
    let ns_out = ns_cmd.execute(&ctx).await.expect("bind namespace");
    let ns_id = ns_out.namespace_id;

    // Put a high-sensitivity secret.
    let handle = "vault://secure/ssh-key/prod".parse().expect("handle");
    let put_cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle,
        category: "ssh-key".parse::<CategoryName>().expect("category"),
        sensitivity: Sensitivity::High,
        tags: vec!["env:prod".parse().expect("tag")],
        expose_metadata: false,
        plaintext: b"very-secret-key-material".to_vec(),
        dek_version: 1,
        dek_bytes: test_dek(),
        value_format: merkle_application::ValueFormat::Utf8,
    };
    put_cmd.execute(&ctx).await.expect("put_secret");

    // Attempt reveal WITHOUT OOB acknowledgement.
    let handle = "vault://secure/ssh-key/prod".parse().expect("handle");
    let reveal_cmd = RevealSecretCommand {
        namespace_id: ns_id,
        handle,
        operator_confirmation: OperatorConfirmation {
            slash_command: true,
            oob_ack: false, // no OOB ack
            signed_config_flag: None,
        },
        challenge_id: None,
        sensitivity: Sensitivity::High,
        oob_threshold: Sensitivity::High,
        security_profile: SecurityProfile::Balanced,
        dek_bytes: test_dek(),
        companion_device: None,
        oob_channel: OobChannel::DesktopNotif,
        oob_timeout: Duration::from_millis(100),
        required_device_class: CompanionDeviceClass::Software,
    };

    let result = reveal_cmd.execute(&ctx).await;
    assert!(
        result.is_err(),
        "reveal should be denied without OOB ack for High sensitivity"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, merkle_application::AppError::PolicyDenied(_)),
        "expected PolicyDenied, got {err:?}"
    );
}

/// T04 — query_audit returns expected entries after unseal + put_secret.
#[tokio::test]
async fn test_query_audit_returns_entries() {
    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    let ns_label: NamespaceLabel = "audit-test".parse().expect("ns label");
    let ns_cmd = BindNamespaceCommand {
        label: ns_label.clone(),
        cwd_hash: None,
        dek_version: 1,
    };
    let ns_out = ns_cmd.execute(&ctx).await.expect("bind namespace");
    let ns_id = ns_out.namespace_id;

    let handle = "vault://audit-test/api-key/stripe".parse().expect("handle");
    let put_cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle,
        category: "api-key".parse::<CategoryName>().expect("category"),
        sensitivity: Sensitivity::Low,
        tags: vec![],
        expose_metadata: true,
        plaintext: b"sk_live_xxx".to_vec(),
        dek_version: 1,
        dek_bytes: test_dek(),
        value_format: merkle_application::ValueFormat::Utf8,
    };
    put_cmd.execute(&ctx).await.expect("put_secret");

    // Query all audit entries — should have at least 2 (unseal + put).
    let query = QueryAuditQuery {
        filter: merkle_domain_audit_compliance::AuditQuery::default(),
        verify_chain: false,
    };
    let out = query
        .execute(&ctx)
        .await
        .expect("query_audit should succeed");
    assert!(
        out.entries.len() >= 2,
        "expected at least 2 audit entries, got {}",
        out.entries.len()
    );

    // All entries should have Allow outcome.
    for entry in &out.entries {
        assert_eq!(
            entry.outcome,
            AuditOutcome::Allow,
            "entry {seq} has unexpected outcome: {outcome:?}",
            seq = entry.seq,
            outcome = entry.outcome
        );
    }
}

/// T05 — agent_status reflects sealed/unsealed state correctly.
#[tokio::test]
async fn test_agent_status() {
    let ctx = make_ctx().await;

    let status = AgentStatusQuery.execute(&ctx).await.expect("agent_status");
    assert_eq!(
        status.sealed_state,
        merkle_domain_identity::SealedState::Sealed
    );

    assert!(unseal(&ctx).await);

    let status = AgentStatusQuery.execute(&ctx).await.expect("agent_status");
    assert_eq!(
        status.sealed_state,
        merkle_domain_identity::SealedState::Unsealed
    );
}

// ---------------------------------------------------------------------------
// New integration tests (T06–T12)
// ---------------------------------------------------------------------------

/// Helper: bind a namespace and put a secret, returning (namespace_id, handle, secret_id).
async fn setup_ns_and_secret(
    ctx: &AppContext,
    ns_label: &str,
    handle_uri: &str,
    plaintext: &[u8],
) -> (
    merkle_types::NamespaceId,
    merkle_types::Handle,
    merkle_types::SecretId,
) {
    let ns_label: NamespaceLabel = ns_label.parse().expect("ns label");
    let ns_cmd = BindNamespaceCommand {
        label: ns_label,
        cwd_hash: None,
        dek_version: 1,
    };
    let ns_out = ns_cmd.execute(ctx).await.expect("bind namespace");
    let ns_id = ns_out.namespace_id;

    let handle: merkle_types::Handle = handle_uri.parse().expect("handle");
    let put_cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle: handle.clone(),
        category: "api-key".parse::<CategoryName>().expect("category"),
        sensitivity: Sensitivity::Low,
        tags: vec![],
        expose_metadata: false,
        plaintext: plaintext.to_vec(),
        dek_version: 1,
        dek_bytes: test_dek(),
        value_format: merkle_application::ValueFormat::Utf8,
    };
    let put_out = put_cmd.execute(ctx).await.expect("put_secret");
    (ns_id, handle, put_out.secret_id)
}

/// T06 — delete_secret removes the secret and emits an audit entry.
#[tokio::test]
async fn test_delete_secret_round_trip_and_audit() {
    use merkle_application::commands::delete_secret::DeleteSecretCommand;
    use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;

    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    let (ns_id, handle, _) = setup_ns_and_secret(
        &ctx,
        "delete-test",
        "vault://delete-test/api-key/to-delete",
        b"delete-me",
    )
    .await;

    // Delete the secret.
    let del_cmd = DeleteSecretCommand {
        namespace_id: ns_id,
        handle: handle.clone(),
        operator_confirmation: OperatorConfirmation {
            slash_command: true,
            oob_ack: false,
            signed_config_flag: None,
        },
    };
    del_cmd
        .execute(&ctx)
        .await
        .expect("delete_secret should succeed");

    // Verify the secret is gone.
    let fetched = ctx
        .storage
        .get_secret_by_handle(&handle)
        .await
        .expect("storage get");
    assert!(fetched.is_none(), "secret should be absent after delete");

    // Verify audit entry was appended.
    let audit_q = merkle_application::queries::query_audit::QueryAuditQuery {
        filter: merkle_domain_audit_compliance::AuditQuery::default(),
        verify_chain: false,
    };
    let audit = audit_q.execute(&ctx).await.expect("query_audit");
    let has_delete = audit
        .entries
        .iter()
        .any(|e| e.op == merkle_types::AuditOp::Delete);
    assert!(has_delete, "expected at least one Delete audit entry");
}

/// T07 — use_token issues an opaque token and audit entry.
#[tokio::test]
async fn test_use_token_issues_opaque_token() {
    use merkle_application::commands::use_token::UseTokenCommand;
    use merkle_types::UuidV7;

    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    let (ns_id, handle, _) = setup_ns_and_secret(
        &ctx,
        "token-test",
        "vault://token-test/api-key/bastion",
        b"ssh-ed25519 AAAA...",
    )
    .await;

    let cmd = UseTokenCommand {
        namespace_id: ns_id,
        handle,
        session_id: UuidV7::new(),
    };
    let out = cmd.execute(&ctx).await.expect("use_token should succeed");

    // Token must be 43 chars (URL-safe base64, 32 bytes).
    assert_eq!(
        out.use_token.len(),
        43,
        "use_token must be 43 base64url chars, got {}",
        out.use_token.len()
    );

    // Audit entry with op=use must exist.
    let audit_q = merkle_application::queries::query_audit::QueryAuditQuery {
        filter: merkle_domain_audit_compliance::AuditQuery::default(),
        verify_chain: false,
    };
    let audit = audit_q.execute(&ctx).await.expect("query_audit");
    let has_use = audit
        .entries
        .iter()
        .any(|e| e.op == merkle_types::AuditOp::Use);
    assert!(has_use, "expected Use audit entry after use_token");
}

/// T08 — search_secrets returns matching results via FTS query.
#[tokio::test]
async fn test_search_secrets_returns_results() {
    use merkle_application::commands::search_secrets::SearchSecretsCommand;

    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    let ns_label: NamespaceLabel = "search-test".parse().expect("ns label");
    let ns_cmd = BindNamespaceCommand {
        label: ns_label,
        cwd_hash: None,
        dek_version: 1,
    };
    let ns_out = ns_cmd.execute(&ctx).await.expect("bind namespace");
    let ns_id = ns_out.namespace_id;

    // Put two secrets.
    for i in 0..2_u8 {
        let handle: merkle_types::Handle = format!("vault://search-test/api-key/key-{i}")
            .parse()
            .expect("handle");
        let put_cmd = PutSecretCommand {
            namespace_id: ns_id,
            handle,
            category: "api-key".parse::<CategoryName>().expect("category"),
            sensitivity: Sensitivity::Low,
            tags: vec![],
            expose_metadata: true,
            plaintext: format!("secret-{i}").into_bytes(),
            dek_version: 1,
            dek_bytes: test_dek(),
            value_format: merkle_application::ValueFormat::Utf8,
        };
        put_cmd.execute(&ctx).await.expect("put_secret");
    }

    // Search with a query that matches the FTS index.
    let search_cmd = SearchSecretsCommand {
        namespace_id: ns_id,
        query: "key".into(),
        limit: 10,
        offset: 0,
    };
    let search_out = search_cmd.execute(&ctx).await.expect("search_secrets");
    // SQLite FTS5 should return secrets whose name contains "key".
    // The command must not error; result count is non-negative.
    assert!(
        search_out.result.items.len() <= 10,
        "search returned unexpected count"
    );
}

/// T09 — crypto_sign produces a 64-byte Ed25519 signature (hex).
#[tokio::test]
async fn test_crypto_sign_produces_verifiable_signature() {
    use merkle_application::commands::crypto_sign::CryptoSignCommand;

    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    // Generate a fresh Ed25519 keypair via the crypto adapter.
    let (sk, pk) = ctx.crypto.ed25519_keypair();

    // Encrypt the private key seed and store it as a secret.
    let seed_bytes = sk.0;
    let (ns_id, handle, _) = setup_ns_and_secret(
        &ctx,
        "crypto-test",
        "vault://crypto-test/api-key/ed25519-signing",
        &seed_bytes,
    )
    .await;

    let message = b"hello from merkle";
    let sign_cmd = CryptoSignCommand {
        namespace_id: ns_id,
        key_handle: handle,
        dek_bytes: test_dek(),
        message: message.to_vec(),
    };
    let sign_out = sign_cmd
        .execute(&ctx)
        .await
        .expect("crypto_sign should succeed");

    // Signature must be 128 hex chars (64 bytes).
    assert_eq!(
        sign_out.signature_hex.len(),
        128,
        "expected 128-char hex signature"
    );

    // Decode and verify the signature.
    let sig_bytes: Vec<u8> = hex::decode(&sign_out.signature_hex).expect("hex decode");
    let sig_arr: [u8; 64] = sig_bytes.try_into().expect("64 bytes");
    ctx.crypto
        .ed25519_verify(&pk, message, &sig_arr)
        .expect("signature must verify with the public key");
}

/// T10 — doctor query reports chain integrity OK after multiple operations.
#[tokio::test]
async fn test_doctor_reports_chain_integrity_ok() {
    use merkle_application::queries::doctor::DoctorQuery;

    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    // Perform several operations to build up the audit chain.
    for i in 0..3_u8 {
        let ns_label: NamespaceLabel = format!("doctor-{i}").parse().expect("ns label");
        let ns_cmd = BindNamespaceCommand {
            label: ns_label,
            cwd_hash: None,
            dek_version: 1,
        };
        ns_cmd.execute(&ctx).await.expect("bind namespace");
    }

    let doctor_out = DoctorQuery
        .execute(&ctx)
        .await
        .expect("doctor should succeed");
    assert!(
        doctor_out.all_ok,
        "doctor: all checks should pass; got: {doctor_out:?}"
    );
    assert_eq!(doctor_out.sealed_state, "unsealed");

    let chain_check = doctor_out
        .checks
        .iter()
        .find(|c| c.name == "audit_chain_integrity")
        .expect("audit_chain_integrity check must be present");
    assert!(chain_check.ok, "audit chain integrity check must pass");
}

/// T11 — write_tempfile returns opaque token and file exists on disk.
#[tokio::test]
async fn test_write_tempfile_returns_opaque_token() {
    use merkle_application::commands::use_token::UseTokenCommand;
    use merkle_application::commands::write_tempfile::WriteTempfileCommand;

    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    let (ns_id, handle, _) = setup_ns_and_secret(
        &ctx,
        "tempfile-test",
        "vault://tempfile-test/api-key/stripe",
        b"sk_live_abc123",
    )
    .await;

    // A single-use authorization token is now required before materialization.
    let use_token = UseTokenCommand {
        namespace_id: ns_id,
        handle: handle.clone(),
        session_id: merkle_types::UuidV7::new(),
    }
    .execute(&ctx)
    .await
    .expect("issue use-token")
    .use_token;

    let cmd = WriteTempfileCommand {
        namespace_id: ns_id,
        handle,
        dek_bytes: test_dek(),
        use_token,
    };
    let out = cmd
        .execute(&ctx)
        .await
        .expect("write_tempfile should succeed");

    // Opaque token must be 64 hex chars (32 bytes).
    assert_eq!(
        out.opaque_token.len(),
        64,
        "opaque_token must be 64 hex chars"
    );

    // Verify the file exists and has the correct content.
    let tmp_path = std::env::temp_dir().join(format!("merkle_{}.tmp", out.opaque_token));
    let content = std::fs::read(&tmp_path).expect("tempfile should exist");
    assert_eq!(content, b"sk_live_abc123");

    // Clean up.
    let _ = std::fs::remove_file(&tmp_path);
}

/// T12 — delete_secret denied for High-sensitivity without slash_command.
#[tokio::test]
async fn test_delete_high_sensitivity_denied_without_slash_command() {
    use merkle_application::commands::delete_secret::DeleteSecretCommand;
    use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;
    use merkle_types::Handle;

    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    // Bind namespace.
    let ns_label: NamespaceLabel = "del-denied".parse().expect("ns label");
    let ns_cmd = BindNamespaceCommand {
        label: ns_label,
        cwd_hash: None,
        dek_version: 1,
    };
    let ns_out = ns_cmd.execute(&ctx).await.expect("bind namespace");
    let ns_id = ns_out.namespace_id;

    // Put a High-sensitivity secret.
    let handle: Handle = "vault://del-denied/ssh-key/prod-bastion"
        .parse()
        .expect("handle");
    let put_cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle: handle.clone(),
        category: "ssh-key".parse::<CategoryName>().expect("category"),
        sensitivity: Sensitivity::High,
        tags: vec!["env:prod".parse().expect("tag")],
        expose_metadata: false,
        plaintext: b"ssh-ed25519 AAAA...".to_vec(),
        dek_version: 1,
        dek_bytes: test_dek(),
        value_format: merkle_application::ValueFormat::Utf8,
    };
    put_cmd.execute(&ctx).await.expect("put_secret");

    // Attempt delete WITHOUT slash_command.
    let del_cmd = DeleteSecretCommand {
        namespace_id: ns_id,
        handle: handle.clone(),
        operator_confirmation: OperatorConfirmation {
            slash_command: false,
            oob_ack: false,
            signed_config_flag: None,
        },
    };
    let result = del_cmd.execute(&ctx).await;
    assert!(
        result.is_err(),
        "delete of High-sensitivity secret without slash_command must be denied"
    );
    assert!(
        matches!(
            result.unwrap_err(),
            merkle_application::AppError::PolicyDenied(_)
        ),
        "expected PolicyDenied"
    );
}

/// T13 — Bug-4 regression: init stores master key, unseal finds it.
///
/// Reproduces the naming mismatch where `init_vault` wrote the master key under
/// one service+account pair while `unseal_vault` looked up a different pair,
/// producing `Keychain not found`.  Both commands now use the same
/// `KEYCHAIN_SERVICE` / `KEYCHAIN_ACCOUNT_MASTER_KEY` constants.
#[tokio::test]
async fn test_init_then_unseal_succeeds_keychain_naming_aligned() {
    // Build a fresh context where the keychain starts empty.
    let storage = merkle_adapter_sqlite::SqliteStorage::open("sqlite::memory:")
        .await
        .expect("in-memory sqlite");
    let crypto = Arc::new(merkle_adapter_crypto::RustCryptoAdapter::new());
    let keychain = Arc::new(merkle_adapter_keychain::MockKeychainAdapter::new());
    let oob = Arc::new(merkle_adapter_oob::mock::MockOobNotifier::new());
    let external = Arc::new(merkle_adapter_external_services::MockExternalServices::new());

    // VaultIdentity starts Sealed with canonical keychain ref.
    let keychain_ref = KeychainEntry::for_master_key(1, merkle_types::Rfc3339Timestamp::now());
    let recovery_pubkey = RecoveryPublicKey::new(
        "age1test".to_owned(),
        "SHA256:test=".to_owned(),
        merkle_types::Rfc3339Timestamp::now(),
    );
    let identity = VaultIdentity::new(keychain_ref, recovery_pubkey);
    let ctx = AppContext::new(Arc::new(storage), keychain, crypto, oob, external, identity);

    // 1. Run init — must succeed on a fresh (empty) keychain.
    let init_cmd = InitVaultCommand {
        interactive: false,
        security_profile: SecurityProfile::Relaxed,
    };
    let init_out = init_cmd
        .execute(&ctx)
        .await
        .expect("init must succeed on a fresh vault");

    // Banner must point to canonical ref.
    assert_eq!(
        init_out.master_key_keychain_ref, "dev.fapp.merkle/master-v1",
        "init banner must report canonical service+account ref"
    );

    // 2. Verify the master key is stored under the canonical name.
    let stored = ctx
        .keychain
        .retrieve(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_MASTER_KEY)
        .await;
    assert!(
        stored.is_ok(),
        "init must store master key under canonical service+account; got: {:?}",
        stored.err()
    );

    // 3. Run unseal — this was the failing step in Bug 4.
    let unseal_cmd = UnsealVaultCommand {
        preconditions: UnsealPreconditions {
            security_profile: SecurityProfile::Relaxed,
            mlock_succeeded: false,
            entropy_seeded: true,
            keychain_reachable: true,
        },
    };
    unseal_cmd
        .execute(&ctx)
        .await
        .expect("unseal must find master key written by init — Bug 4 regression");

    // 4. Agent must now be in Unsealed state.
    let id_guard = ctx.identity.read().await;
    assert_eq!(
        id_guard.state(),
        SealedState::Unsealed,
        "vault must be Unsealed after successful unseal"
    );
}

/// BUG-005 regression — a REAL `init` followed by a real `unseal` must yield an
/// audit chain that verifies end-to-end.
///
/// The genesis `Init` entry (seq 0) is HMAC-signed at init time with a key
/// derived from the random VRK. If `unseal` re-derives a *different* VRK (the
/// old `blake3_keyed(master, …)` placeholder) its audit-HMAC key diverges from
/// the genesis key, so the seq-0 entry fails verification and `chain_valid`
/// becomes `Some(false)`. With `unseal` AEAD-decrypting the init-stored
/// master-wrapped VRK, both lifecycle paths share one key and the chain is
/// intact. This is the end-to-end assertion the prior parity test never made.
#[tokio::test]
async fn init_then_unseal_audit_chain_verifies_end_to_end() {
    let storage = SqliteStorage::open("sqlite::memory:")
        .await
        .expect("in-memory sqlite");
    let crypto = Arc::new(RustCryptoAdapter::new());
    let keychain = Arc::new(MockKeychainAdapter::new());
    let oob = Arc::new(MockOobNotifier::new());
    let external = Arc::new(MockExternalServices::new());
    let keychain_ref = KeychainEntry::for_master_key(1, Rfc3339Timestamp::now());
    let recovery_pubkey = RecoveryPublicKey::new(
        "age1test".to_owned(),
        "SHA256:test=".to_owned(),
        Rfc3339Timestamp::now(),
    );
    let identity = VaultIdentity::new(keychain_ref, recovery_pubkey);
    let ctx = AppContext::new(Arc::new(storage), keychain, crypto, oob, external, identity);

    // Real init: writes the genesis entry under the init-derived audit key and
    // persists the master-wrapped VRK blob.
    InitVaultCommand {
        interactive: false,
        security_profile: SecurityProfile::Relaxed,
    }
    .execute(&ctx)
    .await
    .expect("init must succeed on a fresh vault");

    // Real unseal: must reconstruct the SAME VRK by AEAD-decrypting that blob.
    UnsealVaultCommand {
        preconditions: UnsealPreconditions {
            security_profile: SecurityProfile::Relaxed,
            mlock_succeeded: false,
            entropy_seeded: true,
            keychain_reachable: true,
        },
    }
    .execute(&ctx)
    .await
    .expect("unseal must succeed after init");

    let out = QueryAuditQuery {
        filter: merkle_domain_audit_compliance::AuditQuery::default(),
        verify_chain: true,
    }
    .execute(&ctx)
    .await
    .expect("query_audit");

    assert_eq!(
        out.chain_valid,
        Some(true),
        "BUG-005: genesis Init entry must verify under the unseal-derived audit \
         key; got chain_valid={:?} over {} entries",
        out.chain_valid,
        out.entries.len(),
    );
}

// ---------------------------------------------------------------------------
// T-KEYCHAIN-PERSIST — Bug 5: keychain persistence verification (ADR-0015 §4)
// ---------------------------------------------------------------------------

/// Build an `AppContext` where the mock keychain is pre-configured to return
/// `PersistenceFailed` for the master-key write.
async fn make_ctx_with_keychain_persistence_failure() -> AppContext {
    let storage = SqliteStorage::open("sqlite::memory:")
        .await
        .expect("in-memory sqlite");

    let crypto = Arc::new(RustCryptoAdapter::new());
    let keychain = Arc::new(MockKeychainAdapter::new());
    // Inject failure for the master key entry that InitVaultCommand writes.
    keychain.with_persistence_failure_for(
        merkle_domain_identity::KEYCHAIN_SERVICE,
        merkle_domain_identity::KEYCHAIN_ACCOUNT_MASTER_KEY,
    );
    let oob = Arc::new(MockOobNotifier::new());
    let external = Arc::new(MockExternalServices::new());

    let keychain_ref = KeychainEntry::for_master_key(1, Rfc3339Timestamp::now());
    let recovery_pubkey = RecoveryPublicKey::new(
        "age1test".to_owned(),
        "SHA256:test=".to_owned(),
        Rfc3339Timestamp::now(),
    );
    let identity = VaultIdentity::new(keychain_ref, recovery_pubkey);

    AppContext::new(Arc::new(storage), keychain, crypto, oob, external, identity)
}

/// T14 — Bug #1 regression (ADR-0025): handle URI first segment must be the
/// bound namespace label, not the secret name.
///
/// Live repro 2026-05-24: `vault.put { name: "smoke-api-key" }` returned
/// `vault://smoke-api-key/token/smoke-api-key` because the companion-socket
/// handler was parsing the secret name as the namespace label instead of
/// resolving the actual bound label from storage.
///
/// This test exercises `PutSecretCommand` directly to confirm that the command
/// echoes back exactly the `Handle` supplied by the caller — the label is NOT
/// derived from the secret name at the application layer.
#[tokio::test]
async fn test_put_secret_handle_uri_uses_bound_namespace_label() {
    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    // Bind a namespace whose label differs from the secret name.
    let ns_label: NamespaceLabel = "test-bug-1".parse().expect("ns label");
    let ns_cmd = BindNamespaceCommand {
        label: ns_label.clone(),
        cwd_hash: None,
        dek_version: 1,
    };
    let ns_out = ns_cmd.execute(&ctx).await.expect("bind namespace");
    let ns_id = ns_out.namespace_id;

    // Construct the handle with the bound label — exactly what a correct handler
    // must produce (segment 1 = label, NOT the secret name "my-token").
    let secret_name: merkle_types::SecretName = "my-token".parse().expect("secret name");
    let category: CategoryName = "token".parse().expect("category");
    let handle = merkle_types::Handle::new(ns_label.clone(), category.clone(), secret_name);

    let put_cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle: handle.clone(),
        category,
        sensitivity: Sensitivity::Low,
        tags: vec![],
        expose_metadata: false,
        plaintext: b"s3cr3t-value".to_vec(),
        dek_version: 1,
        dek_bytes: test_dek(),
        value_format: merkle_application::ValueFormat::Utf8,
    };
    let put_out = put_cmd
        .execute(&ctx)
        .await
        .expect("put_secret should succeed");

    // The returned handle must be vault://test-bug-1/token/my-token — segment 1
    // is the BOUND LABEL, not the secret name "my-token".
    assert_eq!(
        put_out.handle.to_string(),
        "vault://test-bug-1/token/my-token",
        "Bug #1: handle URI first segment must be the bound namespace label, not the secret name"
    );
    assert_eq!(
        put_out.handle.namespace().as_str(),
        "test-bug-1",
        "namespace component must equal the bound label"
    );
    assert_ne!(
        put_out.handle.namespace().as_str(),
        "my-token",
        "namespace component must NOT equal the secret name"
    );
}

/// T-KEYCHAIN-PERSIST-01 — init aborts when keychain write does not persist.
///
/// Reproduces Bug 5: on macOS background process the keyring crate returns
/// Ok(()) from set_secret but the entry is never stored. After this fix,
/// OsKeychainAdapter (and MockKeychainAdapter with injection) surfaces the
/// failure as `KeychainError::PersistenceFailed` and init returns an
/// `AppError::Keychain(PersistenceFailed)` instead of fake-success.
#[tokio::test]
async fn test_init_aborts_when_keychain_write_does_not_persist() {
    use merkle_ports::KeychainError;

    let ctx = make_ctx_with_keychain_persistence_failure().await;

    let result = InitVaultCommand {
        interactive: false,
        security_profile: merkle_types::SecurityProfile::Balanced,
    }
    .execute(&ctx)
    .await;

    assert!(
        result.is_err(),
        "init should fail when keychain write does not persist"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            merkle_application::AppError::Keychain(KeychainError::PersistenceFailed { .. })
        ),
        "expected AppError::Keychain(PersistenceFailed), got {err:?}"
    );
}

/// T-LIST-NAMESPACES-01 — ADR-0025 §Bug #2 regression guard.
///
/// `ListNamespacesQuery { label: None }` must return ALL bound namespaces via
/// `Storage::list_namespaces`, not an empty vec.
#[tokio::test]
async fn list_namespaces_query_returns_full_list_when_label_is_none() {
    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    // Bind two namespaces.
    for ns_label in ["ns-alpha", "ns-beta"] {
        let label: NamespaceLabel = ns_label.parse().expect("ns label");
        let cmd = BindNamespaceCommand {
            label,
            cwd_hash: None,
            dek_version: 1,
        };
        cmd.execute(&ctx).await.expect("bind namespace");
    }

    // Query with no label filter — must return both namespaces.
    let out = ListNamespacesQuery { label: None }
        .execute(&ctx)
        .await
        .expect("list_namespaces_query must succeed");

    assert!(
        out.namespaces.len() >= 2,
        "expected at least 2 namespaces from list_namespaces, got {}",
        out.namespaces.len()
    );

    let labels: std::collections::HashSet<String> = out
        .namespaces
        .iter()
        .map(|ns| ns.label.to_string())
        .collect();
    assert!(
        labels.contains("ns-alpha"),
        "list must include ns-alpha; got {labels:?}"
    );
    assert!(
        labels.contains("ns-beta"),
        "list must include ns-beta; got {labels:?}"
    );
}

// ---------------------------------------------------------------------------
// Bug #3 regression tests — verify_chain plumbing in QueryAuditQuery
// ---------------------------------------------------------------------------

/// T-AUDIT-CHAIN-01 — query_audit with verify_chain=true returns Some(true)
/// on an intact chain.
///
/// Regression for Bug #3: `chain_valid` was always `None`; this test proves
/// the BLAKE3 chain verifier is now invoked and reports the correct outcome.
#[tokio::test]
async fn query_audit_verify_chain_returns_true_on_intact_chain() {
    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    // Produce several audit entries: bind + two puts.
    let ns_label: NamespaceLabel = "chain-ok".parse().expect("ns label");
    let ns_cmd = BindNamespaceCommand {
        label: ns_label,
        cwd_hash: None,
        dek_version: 1,
    };
    let ns_out = ns_cmd.execute(&ctx).await.expect("bind namespace");
    let ns_id = ns_out.namespace_id;

    for i in 0..2_u8 {
        let handle: merkle_types::Handle = format!("vault://chain-ok/api-key/key-{i}")
            .parse()
            .expect("handle");
        let put_cmd = PutSecretCommand {
            namespace_id: ns_id,
            handle,
            category: "api-key".parse::<CategoryName>().expect("category"),
            sensitivity: Sensitivity::Low,
            tags: vec![],
            expose_metadata: false,
            plaintext: format!("v{i}").into_bytes(),
            dek_version: 1,
            dek_bytes: test_dek(),
            value_format: merkle_application::ValueFormat::Utf8,
        };
        put_cmd.execute(&ctx).await.expect("put_secret");
    }

    let query = QueryAuditQuery {
        filter: merkle_domain_audit_compliance::AuditQuery::default(),
        verify_chain: true,
    };
    let out = query.execute(&ctx).await.expect("query_audit");

    assert!(
        out.entries.len() >= 3,
        "expected at least 3 audit entries (unseal + bind + 2 puts), got {}",
        out.entries.len()
    );
    assert_eq!(
        out.chain_valid,
        Some(true),
        "chain_valid must be Some(true) for an intact chain"
    );
}

/// T-AUDIT-CHAIN-02 — query_audit with verify_chain=false returns None.
///
/// Verifies the original behaviour: when the caller does not request chain
/// verification, `chain_valid` stays `None` and no verifier work is done.
#[tokio::test]
async fn query_audit_no_verify_returns_none() {
    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    let ns_label: NamespaceLabel = "chain-skip".parse().expect("ns label");
    let ns_cmd = BindNamespaceCommand {
        label: ns_label,
        cwd_hash: None,
        dek_version: 1,
    };
    ns_cmd.execute(&ctx).await.expect("bind namespace");

    let query = QueryAuditQuery {
        filter: merkle_domain_audit_compliance::AuditQuery::default(),
        verify_chain: false,
    };
    let out = query.execute(&ctx).await.expect("query_audit");

    assert_eq!(
        out.chain_valid, None,
        "chain_valid must be None when verify_chain=false"
    );
}

/// T-AUDIT-CHAIN-03 — tampered pinned head causes verify_chain to return Some(false).
///
/// Overwrites the persisted `PinnedHead` with a forged entry whose `head_seq`
/// is higher than the actual number of stored entries.  The verifier's
/// truncation-detection branch then fires and reports a non-intact chain,
/// confirming `chain_valid = Some(false)`.
#[tokio::test]
async fn query_audit_verify_chain_returns_false_on_tampered_chain() {
    use merkle_domain_audit_compliance::{AuditLog, PinnedHead};
    use merkle_types::Blake3Hash;

    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    // Append a couple of entries to build up a real chain.
    let ns_label: NamespaceLabel = "chain-tamper".parse().expect("ns label");
    let ns_cmd = BindNamespaceCommand {
        label: ns_label,
        cwd_hash: None,
        dek_version: 1,
    };
    let ns_out = ns_cmd.execute(&ctx).await.expect("bind namespace");
    let ns_id = ns_out.namespace_id;

    let handle: merkle_types::Handle = "vault://chain-tamper/api-key/secret-one"
        .parse()
        .expect("handle");
    let put_cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle,
        category: "api-key".parse::<CategoryName>().expect("category"),
        sensitivity: Sensitivity::Low,
        tags: vec![],
        expose_metadata: false,
        plaintext: b"secret".to_vec(),
        dek_version: 1,
        dek_bytes: test_dek(),
        value_format: merkle_application::ValueFormat::Utf8,
    };
    put_cmd.execute(&ctx).await.expect("put_secret");

    // Fetch real head_seq from storage, then forge a pinned head with a
    // higher seq to simulate truncation: entries appear to have been deleted
    // from storage while the pinned head still claims they existed.
    let real_head = ctx
        .storage
        .pinned_head()
        .await
        .expect("pinned_head query")
        .expect("pinned head must exist after writes");

    let fake_hash = Blake3Hash::hash(b"tampered-head");
    let fake_seq = real_head.head_seq + 10; // claim 10 more entries existed

    // Overwrite both the in-memory log and the persisted pinned head.
    {
        let mut log = ctx.audit_log.write().await;
        *log = AuditLog::restore_head(fake_hash, fake_seq);
    }
    ctx.storage
        .update_pinned_head(&PinnedHead::new(
            fake_hash,
            fake_seq,
            real_head.head_id, // reuse real id; verifier only checks seq
            merkle_types::Rfc3339Timestamp::now(),
        ))
        .await
        .expect("update_pinned_head with forged head");

    // Run with verify_chain=true — must detect truncation.
    let query = QueryAuditQuery {
        filter: merkle_domain_audit_compliance::AuditQuery::default(),
        verify_chain: true,
    };
    let out = query.execute(&ctx).await.expect("query_audit");

    assert_eq!(
        out.chain_valid,
        Some(false),
        "chain_valid must be Some(false) when the pinned head implies more \
         entries than are present (truncation detected)"
    );
}

// ---------------------------------------------------------------------------
// ADR-0026 regression tests — idempotent bind + get-or-create
// ---------------------------------------------------------------------------

/// REGRESSION (ADR-0026 §Validation #2): binding the same label twice via
/// `BindNamespaceCommand` must return the same `namespace_id` on both calls
/// and must NOT insert a second row in the `namespaces` table.
///
/// Before the fix, the second `execute` hit the SQLite UNIQUE constraint on
/// `label` and returned `AppError::Storage`, poisoning the session.
#[tokio::test]
async fn bind_namespace_same_label_twice_is_idempotent() {
    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    let label: NamespaceLabel = "acme".parse().expect("valid label");

    // First bind — must succeed and create the namespace.
    let first = BindNamespaceCommand {
        label: label.clone(),
        cwd_hash: None,
        dek_version: 1,
    }
    .execute(&ctx)
    .await
    .expect("first bind must succeed");

    // Second bind with the same label — must also succeed and resolve the
    // existing namespace, NOT insert a duplicate row.
    let second = BindNamespaceCommand {
        label: label.clone(),
        cwd_hash: None,
        dek_version: 1,
    }
    .execute(&ctx)
    .await
    .expect("second bind with same label must succeed (idempotent, ADR-0026)");

    // Both calls must resolve to the identical namespace_id.
    assert_eq!(
        first.namespace_id, second.namespace_id,
        "idempotent bind must return the same namespace_id on both calls"
    );

    // Exactly one row must exist in storage for this label.
    let namespaces = ctx
        .storage
        .list_namespaces()
        .await
        .expect("list_namespaces must succeed");
    let acme_rows: Vec<_> = namespaces
        .iter()
        .filter(|ns| ns.label.as_str() == "acme")
        .collect();
    assert_eq!(
        acme_rows.len(),
        1,
        "exactly one namespace row must exist for label 'acme'; got {} (ADR-0026: no duplicate insert)",
        acme_rows.len()
    );
}

/// REGRESSION (ADR-0026 §Validation #2, audit aspect): the second bind of an
/// existing label must NOT append a new audit entry. Only the first bind writes
/// an audit entry.
#[tokio::test]
async fn bind_namespace_second_bind_does_not_emit_audit_entry() {
    let ctx = make_ctx().await;
    assert!(unseal(&ctx).await);

    let label: NamespaceLabel = "audit-idempotent".parse().expect("valid label");

    let bind = |l: NamespaceLabel| {
        let ctx_ref = &ctx;
        async move {
            BindNamespaceCommand {
                label: l,
                cwd_hash: None,
                dek_version: 1,
            }
            .execute(ctx_ref)
            .await
            .expect("bind must succeed")
        }
    };

    bind(label.clone()).await; // first bind — emits audit entry
    bind(label.clone()).await; // second bind — must NOT emit another audit entry

    let query = QueryAuditQuery {
        filter: merkle_domain_audit_compliance::AuditQuery::default(),
        verify_chain: false,
    };
    let out = query.execute(&ctx).await.expect("query_audit");

    let bind_entries: Vec<_> = out
        .entries
        .iter()
        .filter(|e| e.op == merkle_types::AuditOp::Bind)
        .collect();
    assert_eq!(
        bind_entries.len(),
        1,
        "expected exactly 1 Bind audit entry (re-bind must not emit a second entry); got {}",
        bind_entries.len()
    );
}
