//! axum `Router` wiring all 19 companion socket endpoints.
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
    AppContext,
    handlers,
    peer_cred,
    problem::{Problem, ProblemType},
};

/// Build the axum `Router` for all 19 companion socket endpoints.
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
        // Reveal
        .route("/v1/reveal", post(handlers::reveal::reveal))
        // Audit
        .route("/v1/audit", get(handlers::audit::query_audit))
        // Backup / restore
        .route("/v1/backup", post(handlers::backup::trigger_backup))
        .route("/v1/backup/snapshots", get(handlers::backup::list_snapshots))
        .route(
            "/v1/backup/restore-plan",
            post(handlers::backup::create_restore_plan),
        )
        .route(
            "/v1/backup/restore",
            post(handlers::backup::execute_restore),
        )
        .with_state(ctx)
        .layer(middleware::from_fn(peer_cred_check))
        .layer(TraceLayer::new_for_http())
}

/// Middleware: extract and verify peer credentials before routing.
///
/// On platforms where no `PeerCredentials` extension was inserted (e.g., test
/// contexts using an in-process transport), falls back to synthetic credentials
/// matching the current process UID so tests can run without a real socket.
///
/// Connections that fail the UID check receive a 403 Problem+JSON response.
async fn peer_cred_check(mut req: Request, next: Next) -> Response {
    let creds = req
        .extensions()
        .get::<Arc<peer_cred::PeerCredentials>>()
        .map_or_else(peer_cred::synthetic, |c| c.as_ref().clone());

    if let Err(reason) = peer_cred::verify(&creds) {
        return Problem {
            kind: ProblemType::RevealDenied,
            title: "Peer credential check failed".into(),
            status: 403,
            detail: reason,
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    }

    req.extensions_mut().insert(creds);
    next.run(req).await
}
