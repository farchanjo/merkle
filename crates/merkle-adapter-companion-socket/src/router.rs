//! axum `Router` wiring all companion socket endpoints.
//!
//! Also defines the `peer_cred_check` middleware that runs before every
//! handler.

use std::sync::Arc;

use axum::{
    Router,
    extract::Request,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use tower_http::trace::TraceLayer;

use crate::{
    AppContext, handlers, peer_cred,
    problem::{Problem, ProblemType},
};

/// Build the axum `Router` for all companion socket endpoints.
///
/// Layers applied (outer to inner):
/// 1. `TraceLayer` — structured HTTP access logging via `tracing`.
/// 2. `peer_cred_check` — rejects any connection whose UID doesn't match the
///    agent process UID before the handler runs.
pub fn build(ctx: Arc<AppContext>) -> Router {
    Router::new()
        // Agent / sealing
        .route("/v1/agent/init", post(handlers::agent::init))
        .route("/v1/agent/status", get(handlers::agent::status))
        .route("/v1/agent/unseal", post(handlers::agent::unseal))
        .route("/v1/agent/seal", post(handlers::agent::seal))
        // Diagnostics — GET /v1/agent/doctor (ADR-0024 gap matrix)
        .route("/v1/agent/doctor", get(handlers::diagnostics::doctor))
        // Namespaces
        .route("/v1/namespaces", get(handlers::namespaces::list_namespaces))
        // Secrets
        .route(
            "/v1/namespaces/{namespace_id}/secrets",
            get(handlers::secrets::list_secrets).post(handlers::secrets::put_secret),
        )
        .route(
            "/v1/namespaces/{namespace_id}/secrets/{handle_encoded}",
            get(handlers::secrets::get_secret).delete(handlers::secrets::delete_secret),
        )
        .route(
            "/v1/namespaces/{namespace_id}/secrets/{handle_encoded}/versions",
            get(handlers::secrets::list_secret_versions),
        )
        .route(
            "/v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rotate",
            post(handlers::secrets::rotate_secret),
        )
        .route(
            "/v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rollback",
            post(handlers::secrets::rollback_secret),
        )
        // Sessions
        .route("/v1/sessions", post(handlers::sessions::create_session))
        .route(
            "/v1/sessions/{session_id}",
            delete(handlers::sessions::close_session),
        )
        // Companion devices (ADR-0020). Pairing (POST) is a separate OOB
        // enrollment ceremony and is intentionally not exposed here.
        .route("/v1/devices", get(handlers::devices::list_devices))
        .route(
            "/v1/devices/{device_id}",
            delete(handlers::devices::revoke_device),
        )
        // Use-tokens (ADR-0024 gap matrix — PR3)
        .route("/v1/use-tokens", post(handlers::use_token::issue_use_token))
        .route(
            "/v1/use-tokens/tempfile",
            post(handlers::use_token::write_tempfile),
        )
        .route("/v1/use-tokens/fifo", post(handlers::use_token::write_fifo))
        .route(
            "/v1/use-tokens/tempfiles/{opaque_token}",
            delete(handlers::use_token::revoke_tempfile),
        )
        // Reveal
        .route("/v1/reveal", post(handlers::reveal::reveal))
        // Audit
        .route("/v1/audit", get(handlers::audit::query_audit))
        .route("/v1/audit/rebaseline", post(handlers::audit::rebaseline))
        // Backup / restore
        .route("/v1/backup", post(handlers::backup::trigger_backup))
        .route(
            "/v1/backup/snapshots",
            get(handlers::backup::list_snapshots),
        )
        .route(
            "/v1/backup/restore-plan",
            post(handlers::backup::create_restore_plan),
        )
        .route(
            "/v1/backup/restore",
            post(handlers::backup::execute_restore),
        )
        // Proxy — SSH (ADR-0024 gap matrix — PR4)
        .route("/v1/proxy/ssh/exec", post(handlers::proxy::ssh_exec))
        .route("/v1/proxy/ssh/copy", post(handlers::proxy::ssh_copy))
        .route(
            "/v1/proxy/ssh/port-forward",
            post(handlers::proxy::port_forward),
        )
        .route("/v1/proxy/ssh/shell", post(handlers::proxy::ssh_shell))
        // Proxy — HTTP
        .route(
            "/v1/proxy/http/request",
            post(handlers::proxy::http_request),
        )
        .route(
            "/v1/proxy/http/download",
            post(handlers::proxy::http_download),
        )
        .route("/v1/proxy/http/upload", post(handlers::proxy::http_upload))
        // Proxy — Spawn
        .route("/v1/proxy/spawn", post(handlers::proxy::spawn))
        // Proxy — Crypto
        .route("/v1/proxy/crypto/sign", post(handlers::proxy::crypto_sign))
        .route(
            "/v1/proxy/crypto/decrypt",
            post(handlers::proxy::crypto_decrypt),
        )
        .with_state(ctx)
        .layer(middleware::from_fn(peer_cred_check))
        .layer(TraceLayer::new_for_http())
}

/// Middleware: verify the peer credentials injected by the accept loop before
/// routing.
///
/// The connection layer ([`crate::serve_with_peer_cred`]) inserts an
/// `Arc<PeerCredentials>` extracted from the kernel at accept time. This
/// middleware FAILS CLOSED: if that extension is absent the request did not
/// arrive through the authenticated socket path, so it is rejected with 403
/// rather than fabricating a passing identity. On success the bare
/// `PeerCredentials` is inserted for the [`crate::extensions::ExtractedPeerCred`]
/// extractor.
async fn peer_cred_check(mut req: Request, next: Next) -> Response {
    let deny = |detail: String| {
        Problem {
            kind: ProblemType::RevealDenied,
            title: "Peer credential check failed".into(),
            status: 403,
            detail,
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response()
    };

    let Some(creds) = req
        .extensions()
        .get::<Arc<peer_cred::PeerCredentials>>()
        .map(|c| c.as_ref().clone())
    else {
        return deny(
            "No peer credentials were attached to this request; the connection \
             did not pass through the authenticated socket layer."
                .into(),
        );
    };

    if let Err(reason) = peer_cred::verify(&creds) {
        return deny(reason);
    }

    req.extensions_mut().insert(creds);
    next.run(req).await
}
