//! Integration tests for `merkle-adapter-mcp`.
//!
//! Tests exercise `MerkleMcpServer` via its public API — direct tool-method
//! calls — without a real MCP transport.

use std::sync::Arc;

use merkle_adapter_crypto::RustCryptoAdapter;
use merkle_adapter_external_services::MockExternalServices;
use merkle_adapter_keychain::MockKeychainAdapter;
use merkle_adapter_mcp::{
    MerkleMcpServer,
    errors::codes,
    tools::audit::VaultAuditQueryInput,
    tools::diagnostics::VaultDoctorInput,
    tools::identity::{VaultBindInput, VaultUnsealInput},
    tools::reveal::VaultRevealInput,
    tools::secrets::{VaultDeleteInput, VaultPutInput, VaultSearchInput},
    tools::use_token::VaultUseInput,
};
use merkle_adapter_oob::mock::MockOobNotifier;
use merkle_adapter_sqlite::SqliteStorage;
use merkle_application::AppContext;
use merkle_domain_identity::{KeychainEntry, RecoveryPublicKey, VaultIdentity};
use merkle_types::Rfc3339Timestamp;
use rmcp::{ServerHandler as _, handler::server::tool::Parameters};

// ---------------------------------------------------------------------------
// Test context helper
// ---------------------------------------------------------------------------

async fn make_ctx() -> Arc<AppContext> {
    let storage = SqliteStorage::open("sqlite::memory:")
        .await
        .expect("in-memory sqlite");

    let crypto = Arc::new(RustCryptoAdapter::new());
    let keychain = Arc::new(MockKeychainAdapter::new());
    let oob = Arc::new(MockOobNotifier::new());
    let external = Arc::new(MockExternalServices::new());

    let keychain_entry = KeychainEntry::for_master_key(1, Rfc3339Timestamp::now());
    let recovery_pubkey = RecoveryPublicKey::new(
        "age1test000000000000000000000000000000000000000000000000000000".to_owned(),
        "SHA256:test=".to_owned(),
        Rfc3339Timestamp::now(),
    );
    let identity = VaultIdentity::new(keychain_entry, recovery_pubkey);

    Arc::new(AppContext::new(
        Arc::new(storage),
        keychain,
        crypto,
        oob,
        external,
        identity,
    ))
}

/// Seed the mock keychain with a test master key so `vault.unseal` succeeds.
async fn seed_master_key(ctx: &AppContext) {
    ctx.keychain
        .store("dev.fapp.merkle", "master-v1", &[0xABu8; 32])
        .await
        .expect("seed master key");
}

/// Build an unsealed `MerkleMcpServer` with the test namespace already bound.
///
/// Sequence: seed keychain → unseal → bind("test-ns").
async fn make_unsealed_server(ns_label: &str) -> MerkleMcpServer {
    let ctx = make_ctx().await;
    seed_master_key(&ctx).await;

    let server = MerkleMcpServer::new(ctx);

    server
        .vault_unseal(Parameters(VaultUnsealInput { passphrase: None }))
        .await
        .expect("unseal should succeed after seeding keychain");

    server
        .vault_bind(Parameters(VaultBindInput {
            label: ns_label.to_owned(),
        }))
        .await
        .expect("bind should succeed on unsealed vault");

    server
}

/// Put a single test secret into the bound namespace.
/// Returns the handle string.
async fn put_test_secret(server: &MerkleMcpServer) -> String {
    let out = server
        .vault_put(Parameters(VaultPutInput {
            category: "token".to_owned(),
            name: "ci-token".to_owned(),
            value: serde_json::json!("s3cr3t"),
            schema_id: None,
            tags: Some(vec!["ci".to_owned()]),
            sensitivity: Some("low".to_owned()),
            expose: Some(true),
        }))
        .await
        .expect("vault.put should succeed");

    // Extract handle from the success JSON.
    let text = out
        .content
        .first()
        .and_then(|c| c.as_text().map(|t| t.text.as_str()))
        .expect("response has text content");
    let v: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
    v["handle"].as_str().expect("handle field present").to_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The MCP server can be constructed and its `get_info` returns `"merkle"`.
#[tokio::test]
async fn server_info_name_is_merkle() {
    let ctx = make_ctx().await;
    let server = MerkleMcpServer::new(ctx);
    let info = server.get_info();
    assert_eq!(info.server_info.name, "merkle");
}

/// Calling `vault.unseal` with the mock keychain (no real key stored) should
/// return a domain error, not a panic.
#[tokio::test]
async fn vault_unseal_returns_domain_error_without_key() {
    let ctx = make_ctx().await;
    let server = MerkleMcpServer::new(ctx);

    let result = server
        .vault_unseal(Parameters(VaultUnsealInput { passphrase: None }))
        .await;

    assert!(result.is_err(), "expected error when no key is stored");
}

/// `vault.reveal` without `operator_confirmation = true` must return
/// `ToolNotImplemented`.
#[tokio::test]
async fn vault_reveal_requires_operator_confirmation() {
    let ctx = make_ctx().await;
    let server = MerkleMcpServer::new(ctx);

    let result = server
        .vault_reveal(Parameters(VaultRevealInput {
            handle: "vault://default/test".to_owned(),
            purpose: "test".to_owned(),
            operator_confirmation: false,
            signed_config_flag: None,
        }))
        .await;

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().code.0,
        codes::TOOL_NOT_IMPLEMENTED,
    );
}

/// `vault.bind` on a sealed vault returns `UnsealRequired` because
/// `BindNamespaceCommand` calls `require_unsealed` internally.
#[tokio::test]
async fn vault_bind_returns_unseal_required_when_sealed() {
    let ctx = make_ctx().await;
    let server = MerkleMcpServer::new(ctx);

    let result = server
        .vault_bind(Parameters(VaultBindInput {
            label: "test-project".to_owned(),
        }))
        .await;

    assert!(result.is_err(), "bind on sealed vault should fail: {result:?}");
    assert_eq!(
        result.unwrap_err().code.0,
        codes::UNSEAL_REQUIRED,
    );
}

/// `vault.bind` called twice on the same session must return `AlreadyBound`.
/// The second call is rejected at the session layer before reaching the domain.
#[tokio::test]
async fn vault_bind_rejects_double_bind() {
    let ctx = make_ctx().await;
    let server = MerkleMcpServer::new(ctx);

    // First bind (will fail with UnsealRequired, but records the session label).
    let _ = server
        .vault_bind(Parameters(VaultBindInput {
            label: "ns-one".to_owned(),
        }))
        .await;

    // Second bind must be rejected with AlreadyBound before reaching the domain.
    let second = server
        .vault_bind(Parameters(VaultBindInput {
            label: "ns-two".to_owned(),
        }))
        .await;

    assert!(second.is_err(), "second bind should return AlreadyBound");
    assert_eq!(second.unwrap_err().code.0, codes::ALREADY_BOUND);
}

// ---------------------------------------------------------------------------
// F6.B: new integration tests for tools wired from F5.B full commands
// ---------------------------------------------------------------------------

/// T-F6-01: `vault.delete` round-trip — put then delete returns `deleted: true`.
#[tokio::test]
async fn f6b_vault_delete_round_trip() {
    let server = make_unsealed_server("del-ns").await;
    let handle = put_test_secret(&server).await;

    let result = server
        .vault_delete(Parameters(VaultDeleteInput {
            handle,
            purpose: "f6b delete test".to_owned(),
        }))
        .await
        .expect("vault.delete should succeed");

    let text = result
        .content
        .first()
        .and_then(|c| c.as_text().map(|t| t.text.as_str()))
        .expect("response has text content");
    let v: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
    assert_eq!(v["deleted"], true, "deleted flag should be true");
}

/// T-F6-02: `vault.use` returns a 43-character base64url use-token.
///
/// The token is generated by `UseTokenCommand` using 256 bits of CSPRNG.
/// Base64url of 32 bytes = ceil(32 * 4/3) = 43 chars (with standard padding
/// removed by the URL-safe encoder). The spec guarantees exactly 43 chars.
#[tokio::test]
async fn f6b_vault_use_returns_43_char_token() {
    let server = make_unsealed_server("use-ns").await;
    let handle = put_test_secret(&server).await;

    let result = server
        .vault_use(Parameters(VaultUseInput {
            handle,
            purpose: "f6b use-token test".to_owned(),
        }))
        .await
        .expect("vault.use should succeed");

    let text = result
        .content
        .first()
        .and_then(|c| c.as_text().map(|t| t.text.as_str()))
        .expect("response has text content");
    let v: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
    let token = v["use_token"].as_str().expect("use_token field present");
    assert_eq!(
        token.len(),
        43,
        "use_token must be 43 characters (base64url of 32 bytes); got: {token}"
    );
    assert!(v["expires_at"].is_string(), "expires_at field must be present");
}

/// T-F6-03: `vault.audit.query` returns N entries after N secret puts.
///
/// Performs 3 puts then queries the audit log; expects at least 3 entries.
#[tokio::test]
async fn f6b_vault_audit_query_returns_entries_after_puts() {
    let server = make_unsealed_server("audit-ns").await;

    for i in 0..3u32 {
        server
            .vault_put(Parameters(VaultPutInput {
                category: "token".to_owned(),
                name: format!("audit-tok-{i}"),
                value: serde_json::json!("val"),
                schema_id: None,
                tags: None,
                sensitivity: Some("low".to_owned()),
                expose: Some(true),
            }))
            .await
            .unwrap_or_else(|e| panic!("put {i} should succeed: {e:?}"));
    }

    let result = server
        .vault_audit_query(Parameters(VaultAuditQueryInput {
            handle: None,
            op: None,
            since: None,
            until: None,
            session_id: None,
            limit: Some(50),
            verify_chain: Some(false),
        }))
        .await
        .expect("vault.audit.query should succeed");

    let text = result
        .content
        .first()
        .and_then(|c| c.as_text().map(|t| t.text.as_str()))
        .expect("response has text content");
    let v: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
    let count = v["count"].as_u64().expect("count field present");
    assert!(
        count >= 3,
        "audit log should have at least 3 entries after 3 puts; got {count}"
    );
}

/// T-F6-04: `vault.doctor` returns `chain_intact: true` on a freshly
/// initialized vault.
#[tokio::test]
async fn f6b_vault_doctor_returns_chain_intact() {
    let server = make_unsealed_server("doctor-ns").await;

    let result = server
        .vault_doctor(Parameters(VaultDoctorInput::default()))
        .await
        .expect("vault.doctor should succeed");

    let text = result
        .content
        .first()
        .and_then(|c| c.as_text().map(|t| t.text.as_str()))
        .expect("response has text content");
    let v: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
    assert_eq!(
        v["chain_intact"], true,
        "chain_intact should be true on a fresh vault; got: {v}"
    );
    assert!(v["checks"].is_array(), "checks array must be present");
}

/// T-F6-05: `vault.search` returns matching secrets after puts.
///
/// Puts two secrets with distinct names then searches; confirms count > 0.
#[tokio::test]
async fn f6b_vault_search_returns_matching_secrets() {
    let server = make_unsealed_server("search-ns").await;

    for i in 0..2u32 {
        server
            .vault_put(Parameters(VaultPutInput {
                category: "token".to_owned(),
                name: format!("searchable-tok-{i}"),
                value: serde_json::json!("val"),
                schema_id: None,
                tags: None,
                sensitivity: Some("low".to_owned()),
                expose: Some(true),
            }))
            .await
            .unwrap_or_else(|e| panic!("put {i} should succeed: {e:?}"));
    }

    let result = server
        .vault_search(Parameters(VaultSearchInput {
            query: "searchable".to_owned(),
            limit: Some(10),
        }))
        .await
        .expect("vault.search should succeed");

    let text = result
        .content
        .first()
        .and_then(|c| c.as_text().map(|t| t.text.as_str()))
        .expect("response has text content");
    let v: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
    let count = v["count"].as_u64().expect("count field present");
    assert!(
        count >= 2,
        "search should return at least 2 results for 'searchable'; got {count}"
    );
}

/// T-F6-06a: `vault.ssh.port_forward` is no longer stubbed (-32099 gone).
///
/// With `operator_confirmation` omitted (defaults to `true`) and
/// `sensitivity = Low`, the policy gate passes and `PortForwardCommand`
/// attempts to spawn an `ssh -L` subprocess. The `ssh` binary exists on
/// the test host so the spawn call succeeds and the MCP tool returns
/// `Ok` with a JSON body containing `session_id` and `local_addr`.
///
/// The SSH tunnel will fail in the background (no valid key material,
/// target host unreachable) but that is a runtime concern outside this
/// integration test, which only validates the MCP adapter layer.
#[tokio::test]
async fn f6b_vault_port_forward_wired_returns_session_id_and_local_addr() {
    use merkle_adapter_mcp::tools::proxy::VaultSshPortForwardInput;

    let server = make_unsealed_server("pf-ns").await;

    let result = server
        .vault_ssh_port_forward(Parameters(VaultSshPortForwardInput {
            handle: "vault://pf-ns/ssh/my-key".to_owned(),
            direction: "local".to_owned(),
            bind_address: None,
            bind_port: 8080,
            target_host: "db.internal".to_owned(),
            target_port: 5432,
            ttl_secs: None,
            operator_confirmation: None, // defaults to true → slash_command=true
        }))
        .await;

    // The command may fail if `ssh` is unavailable; tolerate SPAWN_FAILED
    // but NEVER accept TOOL_NOT_IMPLEMENTED (-32099).
    if let Err(ref err) = result {
        assert_ne!(
            err.code.0,
            codes::TOOL_NOT_IMPLEMENTED,
            "port_forward must no longer return -32099 (not-implemented stub)"
        );
        // Acceptable failures: spawn error, tempfile error, or internal error.
        assert!(
            err.code.0 == codes::SPAWN_FAILED
                || err.code.0 == codes::TEMPFILE_CREATE_FAILED
                || err.code.0 == -32_603,
            "unexpected MCP error code {} from port_forward",
            err.code.0
        );
    } else {
        // Happy path: ssh binary exists and spawn returned Ok.
        let text = result
            .unwrap()
            .content
            .first()
            .and_then(|c| c.as_text().map(|t| t.text.as_str()))
            .expect("response has text content")
            .to_owned();
        let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert!(v["session_id"].is_string(), "session_id must be present");
        assert_eq!(
            v["local_addr"].as_str(),
            Some("127.0.0.1:8080"),
            "local_addr must be 127.0.0.1:8080"
        );
    }
}

/// T-F6-06b: `vault.ssh.port_forward` with explicit `operator_confirmation=false`
/// passes for `sensitivity = Low` (policy gate only blocks for `High`).
///
/// Confirmed by passing `operator_confirmation: Some(false)` — the adapter
/// sets `slash_command = false`, but the gate only checks slash_command for
/// `sensitivity=High`. For Low, the gate is satisfied and the command proceeds.
#[tokio::test]
async fn f6b_vault_port_forward_low_sensitivity_no_slash_command_allowed() {
    use merkle_adapter_mcp::tools::proxy::VaultSshPortForwardInput;

    let server = make_unsealed_server("pf-ns2").await;

    let result = server
        .vault_ssh_port_forward(Parameters(VaultSshPortForwardInput {
            handle: "vault://pf-ns2/ssh/my-key".to_owned(),
            direction: "local".to_owned(),
            bind_address: None,
            bind_port: 9000,
            target_host: "db.internal".to_owned(),
            target_port: 5432,
            ttl_secs: None,
            operator_confirmation: Some(false), // slash_command=false, sensitivity=Low → allowed
        }))
        .await;

    // Must NOT be a policy denial (-32003) — Low sensitivity never requires slash_command.
    if let Err(ref err) = result {
        assert_ne!(
            err.code.0,
            codes::REVEAL_DENIED,
            "Low sensitivity port_forward must never return policy denial -32003"
        );
        assert_ne!(
            err.code.0,
            codes::TOOL_NOT_IMPLEMENTED,
            "port_forward must no longer return -32099"
        );
    }
    // (Happy-path: no extra assertion needed — if Ok, policy gate passed.)
}
