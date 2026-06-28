//! Integration tests for `merkle-adapter-mcp`.
//!
//! The MCP adapter is now a thin translation layer over [`CompanionSocketClient`];
//! it contains no domain logic. Tests therefore fall into two tiers:
//!
//! **Tier 1 — pure unit (no socket):** session-state invariants, error-code
//! mappings, and guards executed before the socket is contacted.
//!
//! **Tier 2 — unreachable-agent smoke (nonexistent socket):** tools that reach
//! the socket return [`codes::AGENT_UNREACHABLE`] when no agent is running.
//! These confirm the adapter wiring is correct without requiring a live agent.

use std::{path::PathBuf, sync::Arc};

use merkle_adapter_mcp::{
    MerkleMcpServer,
    errors::codes,
    tools::audit::VaultAuditQueryInput,
    tools::diagnostics::VaultDoctorInput,
    tools::identity::{VaultBindInput, VaultSealInput, VaultUnsealInput},
    tools::proxy::{VaultSshExecInput, VaultSshPortForwardInput},
    tools::reveal::VaultRevealInput,
    tools::secrets::{VaultDeleteInput, VaultListInput, VaultPutInput, VaultSearchInput},
    tools::use_token::VaultUseInput,
};
use merkle_companion_client::CompanionSocketClient;
use rmcp::{ServerHandler as _, handler::server::tool::Parameters};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a `MerkleMcpServer` backed by a socket that does not exist.
/// Any call that reaches the socket returns `AGENT_UNREACHABLE`.
fn unreachable_server() -> MerkleMcpServer {
    let client = Arc::new(CompanionSocketClient::new(PathBuf::from(
        "/nonexistent/merkle-test.sock",
    )));
    MerkleMcpServer::new(client)
}

// ---------------------------------------------------------------------------
// Tier 1: pure unit tests (no socket contact)
// ---------------------------------------------------------------------------

/// `get_info` must report server name `"merkle"`.
#[tokio::test]
async fn server_info_name_is_merkle() {
    let server = unreachable_server();
    let info = server.get_info();
    assert_eq!(info.server_info.name, "merkle");
}

/// Build a `_meta` carrying the client-injected operator-confirmation marker,
/// as the `/merkle-reveal` and `/merkle-delete` slash commands do. The LLM
/// cannot produce this — it only fills the tool `arguments` object (MERK-001).
fn confirmed_meta() -> rmcp::model::Meta {
    let mut meta = rmcp::model::Meta::new();
    meta.insert(
        merkle_adapter_mcp::OPERATOR_CONFIRMATION_META_KEY.to_owned(),
        serde_json::Value::Bool(true),
    );
    meta
}

/// `vault.reveal` without client-injected `_meta` provenance must be rejected
/// with `INVALID_PARAMS` (-32602) before contacting the socket. A model can only
/// fill the tool `arguments`, never the request `_meta` (MERK-001).
#[tokio::test]
async fn vault_reveal_requires_operator_confirmation() {
    let server = unreachable_server();

    let err = server
        .vault_reveal(
            Parameters(VaultRevealInput {
                handle: "vault://default/token/test".to_owned(),
                purpose: "test".to_owned(),
            }),
            rmcp::model::Meta::new(),
        )
        .await
        .expect_err("should return error without _meta provenance");

    assert_eq!(
        err.code.0, -32602,
        "expected INVALID_PARAMS (-32602); got {}",
        err.code.0
    );
}

/// `vault.bind` called twice on the same session after a successful first bind
/// must return `ALREADY_BOUND` (-32008). The second call is rejected at the
/// session guard before the socket is contacted (ADR-0026 "at most once" invariant).
///
/// NOTE: the previous version of this test asserted that a second bind was
/// rejected even when the first bind FAILED. That was the broken behaviour fixed
/// by ADR-0026: a failed first bind must NOT lock the session. This test now
/// uses a pre-bound server (direct state injection) to verify the guard fires
/// only after a committed, successful bind.
#[tokio::test]
async fn vault_bind_rejects_double_bind_after_successful_first_bind() {
    let server = pre_bound_unreachable_server().await;

    // Session is already successfully bound; a second bind must be rejected.
    let err = server
        .vault_bind(Parameters(VaultBindInput {
            label: "ns-two".to_owned(),
        }))
        .await
        .expect_err("second bind after success must return AlreadyBound");

    assert_eq!(
        err.code.0,
        codes::ALREADY_BOUND,
        "expected ALREADY_BOUND (-32008); got {}",
        err.code.0
    );
}

/// Tools that require a bound namespace return `NAMESPACE_NOT_BOUND` (-32005)
/// immediately, without contacting the socket, when `vault.bind` has not
/// been called.
#[tokio::test]
async fn tools_return_namespace_not_bound_before_bind() {
    let server = unreachable_server();

    // vault.put — requires namespace.
    let err = server
        .vault_put(Parameters(VaultPutInput {
            category: "token".to_owned(),
            name: "tok".to_owned(),
            value: serde_json::json!("secret"),
            schema_id: None,
            tags: None,
            sensitivity: None,
            expose: None,
        }))
        .await
        .expect_err("vault.put without bind must return error");

    assert_eq!(
        err.code.0,
        codes::NAMESPACE_NOT_BOUND,
        "expected NAMESPACE_NOT_BOUND (-32005); got {}",
        err.code.0
    );

    // vault.list — also requires namespace.
    let err2 = server
        .vault_list(Parameters(VaultListInput {
            category: None,
            tags: None,
            name_pattern: None,
            expires_before: None,
            sensitivity: None,
            fts_query: None,
            limit: None,
        }))
        .await
        .expect_err("vault.list without bind must return error");

    assert_eq!(
        err2.code.0,
        codes::NAMESPACE_NOT_BOUND,
        "expected NAMESPACE_NOT_BOUND (-32005); got {}",
        err2.code.0
    );
}

/// `vault.reveal` with client-injected `_meta` provenance but without a bound
/// namespace returns `NAMESPACE_NOT_BOUND` (-32005).
#[tokio::test]
async fn vault_reveal_unbound_returns_namespace_not_bound() {
    let server = unreachable_server();

    let err = server
        .vault_reveal(
            Parameters(VaultRevealInput {
                handle: "vault://default/token/test".to_owned(),
                purpose: "unit-test".to_owned(),
            }),
            confirmed_meta(),
        )
        .await
        .expect_err("reveal without bind must return error");

    assert_eq!(
        err.code.0,
        codes::NAMESPACE_NOT_BOUND,
        "expected NAMESPACE_NOT_BOUND (-32005); got {}",
        err.code.0
    );
}

// ---------------------------------------------------------------------------
// Tier 2: unreachable-agent smoke tests
// ---------------------------------------------------------------------------
//
// These call tools that pass all session guards, then contact the socket.
// Because no agent is listening, the socket layer returns AGENT_UNREACHABLE.
//
// They confirm:
//   a) the tool implementation compiles with the current input struct shapes,
//   b) the error-mapping path from ClientError::Unreachable is wired correctly,
//   c) session-guard code paths for bound sessions are reachable.

/// Build a server whose session already has a synthesised binding so tools
/// that require `namespace_id` + `session_id` will pass the session guard
/// and proceed to the socket call.
async fn pre_bound_unreachable_server() -> MerkleMcpServer {
    let server = unreachable_server();
    // Directly mutate session state to simulate a successful bind.
    {
        let mut session = server.session.write().await;
        let ns_id = uuid::Uuid::nil();
        let sid = uuid::Uuid::nil();
        // `bind` records the label and sets `namespace_bound = true`.
        session
            .bind("smoke-ns".to_owned())
            .expect("first bind must succeed");
        // `set_binding` stores the UUID pair.
        session.set_binding(ns_id, sid);
    }
    server
}

/// `vault.unseal` with the socket absent returns `AGENT_UNREACHABLE` (-32100).
#[tokio::test]
async fn vault_unseal_returns_agent_unreachable() {
    let server = unreachable_server();

    let err = server
        .vault_unseal(Parameters(VaultUnsealInput { passphrase: None }))
        .await
        .expect_err("unseal to dead socket must return error");

    assert_eq!(
        err.code.0,
        codes::AGENT_UNREACHABLE,
        "expected AGENT_UNREACHABLE (-32100); got {}",
        err.code.0
    );
}

/// `vault.seal` with the socket absent returns `AGENT_UNREACHABLE`.
#[tokio::test]
async fn vault_seal_returns_agent_unreachable() {
    let server = unreachable_server();

    let err = server
        .vault_seal(Parameters(VaultSealInput { reason: None }))
        .await
        .expect_err("seal to dead socket must return error");

    assert_eq!(
        err.code.0,
        codes::AGENT_UNREACHABLE,
        "expected AGENT_UNREACHABLE (-32100); got {}",
        err.code.0
    );
}

/// `vault.bind` with the socket absent returns `AGENT_UNREACHABLE`.
#[tokio::test]
async fn vault_bind_first_call_returns_agent_unreachable() {
    let server = unreachable_server();

    let err = server
        .vault_bind(Parameters(VaultBindInput {
            label: "dead-ns".to_owned(),
        }))
        .await
        .expect_err("bind to dead socket must return error");

    assert_eq!(
        err.code.0,
        codes::AGENT_UNREACHABLE,
        "expected AGENT_UNREACHABLE (-32100); got {}",
        err.code.0
    );
}

/// `vault.use` with a pre-bound session and dead socket returns
/// `AGENT_UNREACHABLE` (-32100).
#[tokio::test]
async fn vault_use_returns_agent_unreachable() {
    let server = pre_bound_unreachable_server().await;

    let err = server
        .vault_use(Parameters(VaultUseInput {
            handle: "vault://smoke-ns/token/ci-token".to_owned(),
            purpose: "smoke test".to_owned(),
        }))
        .await
        .expect_err("vault.use to dead socket must return error");

    assert_eq!(
        err.code.0,
        codes::AGENT_UNREACHABLE,
        "expected AGENT_UNREACHABLE (-32100); got {}",
        err.code.0
    );
}

/// `vault.delete` with a pre-bound session and dead socket returns
/// `AGENT_UNREACHABLE`.
#[tokio::test]
async fn vault_delete_returns_agent_unreachable() {
    let server = pre_bound_unreachable_server().await;

    let err = server
        .vault_delete(
            Parameters(VaultDeleteInput {
                handle: "vault://smoke-ns/token/tok".to_owned(),
                purpose: "smoke".to_owned(),
            }),
            confirmed_meta(),
        )
        .await
        .expect_err("vault.delete to dead socket must return error");

    assert_eq!(
        err.code.0,
        codes::AGENT_UNREACHABLE,
        "expected AGENT_UNREACHABLE (-32100); got {}",
        err.code.0
    );
}

/// `vault.delete` without client-injected `_meta` provenance is rejected up
/// front and never reaches the agent (no autonomous deletion by the model).
#[tokio::test]
async fn vault_delete_without_confirmation_is_rejected() {
    let server = pre_bound_unreachable_server().await;

    let err = server
        .vault_delete(
            Parameters(VaultDeleteInput {
                handle: "vault://smoke-ns/token/tok".to_owned(),
                purpose: "smoke".to_owned(),
            }),
            rmcp::model::Meta::new(),
        )
        .await
        .expect_err("vault.delete without confirmation must be rejected");

    // Must be the up-front invalid-params gate, NOT a transport error — proving
    // the call was refused before any socket I/O.
    assert_ne!(
        err.code.0,
        codes::AGENT_UNREACHABLE,
        "delete must be refused by the confirmation gate, not the dead socket"
    );
}

/// `vault.audit.query` with a pre-bound session and dead socket returns
/// `AGENT_UNREACHABLE`. Also compiles the new `VaultAuditQueryInput` shape
/// (no `since`/`until` fields).
#[tokio::test]
async fn vault_audit_query_returns_agent_unreachable() {
    let server = pre_bound_unreachable_server().await;

    let err = server
        .vault_audit_query(Parameters(VaultAuditQueryInput {
            handle: None,
            op: None,
            session_id: None,
            outcome: None,
            limit: Some(10),
            verify_chain: Some(false),
        }))
        .await
        .expect_err("vault.audit.query to dead socket must return error");

    assert_eq!(
        err.code.0,
        codes::AGENT_UNREACHABLE,
        "expected AGENT_UNREACHABLE (-32100); got {}",
        err.code.0
    );
}

/// `vault.doctor` with a dead socket returns `AGENT_UNREACHABLE`.
#[tokio::test]
async fn vault_doctor_returns_agent_unreachable() {
    let server = unreachable_server();

    let err = server
        .vault_doctor(Parameters(VaultDoctorInput::default()))
        .await
        .expect_err("vault.doctor to dead socket must return error");

    assert_eq!(
        err.code.0,
        codes::AGENT_UNREACHABLE,
        "expected AGENT_UNREACHABLE (-32100); got {}",
        err.code.0
    );
}

/// `vault.search` with a pre-bound session and dead socket returns
/// `AGENT_UNREACHABLE`.
#[tokio::test]
async fn vault_search_returns_agent_unreachable() {
    let server = pre_bound_unreachable_server().await;

    let err = server
        .vault_search(Parameters(VaultSearchInput {
            query: "test".to_owned(),
            limit: Some(10),
            offset: None,
        }))
        .await
        .expect_err("vault.search to dead socket must return error");

    assert_eq!(
        err.code.0,
        codes::AGENT_UNREACHABLE,
        "expected AGENT_UNREACHABLE (-32100); got {}",
        err.code.0
    );
}

/// `vault.ssh.exec` with a pre-bound session and dead socket returns
/// `AGENT_UNREACHABLE`. Compiles the new `VaultSshExecInput` shape.
#[tokio::test]
async fn vault_ssh_exec_returns_agent_unreachable() {
    let server = pre_bound_unreachable_server().await;

    let err = server
        .vault_ssh_exec(Parameters(VaultSshExecInput {
            handle: "vault://smoke-ns/ssh/my-key".to_owned(),
            target: "bastion.example.com:22".to_owned(),
            command: "echo hello".to_owned(),
            args: None,
            env: None,
            timeout_secs: None,
        }))
        .await
        .expect_err("vault.ssh.exec to dead socket must return error");

    assert_eq!(
        err.code.0,
        codes::AGENT_UNREACHABLE,
        "expected AGENT_UNREACHABLE (-32100); got {}",
        err.code.0
    );
}

// ---------------------------------------------------------------------------
// ADR-0026 regression tests: idempotent bind + session-state atomicity
// ---------------------------------------------------------------------------

/// REGRESSION (ADR-0026): a `vault.bind` that fails at the Companion Socket
/// layer must NOT set `namespace_bound = true` in `SessionState`.
///
/// Before the fix, Phase 1 set `namespace_bound = true` before the socket call.
/// After the socket call failed, Phase 3 was skipped, leaving
/// `namespace_bound=true, namespace_id=None` — the "half-bound" poison state.
///
/// This test verifies:
/// a) A failed bind (unreachable socket) leaves the session fully unbound.
/// b) A second `vault.bind` call after the failure returns `AGENT_UNREACHABLE`,
///    not `ALREADY_BOUND` — i.e. the session is NOT permanently locked.
#[tokio::test]
async fn vault_bind_socket_failure_leaves_session_unbound() {
    let server = unreachable_server();

    // First bind — socket is unreachable, so this must fail.
    let err = server
        .vault_bind(Parameters(VaultBindInput {
            label: "baremetal-v2".to_owned(),
        }))
        .await
        .expect_err("bind to dead socket must return error");

    assert_eq!(
        err.code.0,
        codes::AGENT_UNREACHABLE,
        "expected AGENT_UNREACHABLE (-32100) on first bind; got {}",
        err.code.0
    );

    // Session must be completely unbound: namespace_id must be None.
    {
        let session = server.session.read().await;
        assert!(
            session.namespace_id().is_none(),
            "namespace_id must remain None after failed bind (ADR-0026: no half-bound state)"
        );
        assert!(
            !session.is_bound(),
            "namespace_bound must remain false after failed bind (ADR-0026: no half-bound state)"
        );
    }

    // Second bind attempt must also reach the socket (returning AGENT_UNREACHABLE),
    // NOT be rejected at the session guard with ALREADY_BOUND.
    let err2 = server
        .vault_bind(Parameters(VaultBindInput {
            label: "baremetal-v2".to_owned(),
        }))
        .await
        .expect_err("second bind after failure must also return an error");

    assert_eq!(
        err2.code.0,
        codes::AGENT_UNREACHABLE,
        "expected AGENT_UNREACHABLE (-32100) on retry; got {} (ALREADY_BOUND = {} would mean the session is poisoned)",
        err2.code.0,
        codes::ALREADY_BOUND
    );
}

/// REGRESSION (ADR-0026): after a successful bind the session-state fields
/// `namespace_bound`, `namespace_label`, and `namespace_id` must all be set
/// consistently. This test uses a pre-bound session (simulated via direct
/// state mutation) and confirms the invariant holds.
#[tokio::test]
async fn vault_bind_session_state_is_consistent_after_success() {
    let server = unreachable_server();

    // Simulate a fully committed bind (the new two-phase commit path).
    // Use nil UUIDs since the uuid crate in this workspace doesn't enable v4.
    {
        let mut session = server.session.write().await;
        let ns_id = uuid::Uuid::nil();
        let sid = uuid::Uuid::nil();
        session.commit_binding("acme".to_owned(), ns_id, sid);
    }

    // All three fields must be set.
    {
        let session = server.session.read().await;
        assert!(session.is_bound(), "namespace_bound must be true");
        assert_eq!(
            session.namespace_label(),
            Some("acme"),
            "namespace_label must match"
        );
        assert!(
            session.namespace_id().is_some(),
            "namespace_id must be Some after commit_binding"
        );
        assert!(
            session.session_id().is_some(),
            "session_id must be Some after commit_binding"
        );
    }

    // A second bind on the already-bound session must return ALREADY_BOUND.
    let err = server
        .vault_bind(Parameters(VaultBindInput {
            label: "other-label".to_owned(),
        }))
        .await
        .expect_err("second bind must return AlreadyBound");

    assert_eq!(
        err.code.0,
        codes::ALREADY_BOUND,
        "expected ALREADY_BOUND (-32008); got {}",
        err.code.0
    );
}

/// `vault.ssh.port_forward` with a pre-bound session and dead socket returns
/// `AGENT_UNREACHABLE`. Compiles the new `VaultSshPortForwardInput` shape
/// (`target`, `local_port`, `remote_host`, `remote_port` — no `direction`,
/// `bind_address`, `bind_port`, `target_host`, or `target_port`).
#[tokio::test]
async fn vault_ssh_port_forward_returns_agent_unreachable() {
    let server = pre_bound_unreachable_server().await;

    let err = server
        .vault_ssh_port_forward(Parameters(VaultSshPortForwardInput {
            handle: "vault://smoke-ns/ssh/my-key".to_owned(),
            target: "bastion.example.com:22".to_owned(),
            local_port: 8080,
            remote_host: "db.internal".to_owned(),
            remote_port: 5432,
            ttl_secs: None,
            operator_confirmation: None,
        }))
        .await
        .expect_err("vault.ssh.port_forward to dead socket must return error");

    assert_eq!(
        err.code.0,
        codes::AGENT_UNREACHABLE,
        "expected AGENT_UNREACHABLE (-32100); got {}",
        err.code.0
    );
}
