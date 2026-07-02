//! Handlers for session lease endpoints:
//!
//! - `POST   /v1/sessions`
//! - `DELETE /v1/sessions/{session_id}`
//!
//! Sessions are backed by `BindNamespaceCommand` — each `POST /v1/sessions`
//! call either binds a new namespace (or retrieves an existing one) and returns
//! a session descriptor. `DELETE /v1/sessions/{id}` is a no-op at this phase
//! because namespace bindings are persistent; a future unbind command will be
//! wired in Phase 6.B.
//!
//! # MCP `vault.bind` mapping (ADR-0024 §Note 1)
//!
//! The MCP `vault.bind` tool maps to `BindNamespaceCommand`. Rather than
//! introducing a parallel bind endpoint, the MCP Adapter MUST call
//! `POST /v1/sessions` with:
//!
//! - `cwd_hash`: hex-SHA256 of `std::env::current_dir()` at MCP server startup.
//! - `namespace_label`: the user-supplied label from `vault.bind`, if any.
//!
//! This preserves the cwd-scoped namespace semantics defined in ADR-0002 and
//! avoids a duplicated bind surface. The 1:1 `session_id == namespace_id`
//! mapping is a Phase 6 simplification; Phase 6.B will introduce a separate
//! session table with per-client TTLs.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use merkle_application::commands::bind_namespace::BindNamespaceCommand;
use merkle_types::SecurityProfile;
use std::sync::Arc;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    AppContext, consumer_gate,
    dto::{CloseSessionResponse, CreateSessionRequest, CreateSessionResponse},
    extensions::ExtractedPeerCred,
    problem::app_error_to_problem,
};

/// `POST /v1/sessions`
///
/// Called by the MCP Adapter after the `notifications/initialized` handshake.
/// Creates or re-binds a namespace for the given `cwd_hash`.
#[instrument(skip(ctx, peer, body))]
pub async fn create_session(
    State(ctx): State<Arc<AppContext>>,
    ExtractedPeerCred(peer): ExtractedPeerCred,
    Json(body): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    // Derive a namespace label from the optional namespace_label field or the
    // cwd_hash prefix so that each distinct project directory gets its own
    // namespace. The fallback uses a char-safe prefix (MERK-006) so a
    // multibyte cwd_hash cannot panic on a non-char-boundary byte index.
    let raw_label = body
        .namespace_label
        .as_deref()
        .map_or_else(|| body.cwd_hash_slug(), str::to_owned);

    // NamespaceLabel requires DNS-safe format; sanitize to [a-z0-9-].
    let sanitized = raw_label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned();

    let label: merkle_types::NamespaceLabel = match sanitized.parse() {
        Ok(l) => l,
        Err(_) => {
            // Absolute fallback: use a fixed label when sanitization produces garbage.
            match "default-session".parse() {
                Ok(l) => l,
                Err(e) => {
                    return crate::problem::Problem {
                        kind: crate::problem::ProblemType::SchemaValidationFailed,
                        title: "Invalid namespace label".into(),
                        status: 400,
                        detail: e.to_string(),
                        instance: None,
                        hint: None,
                        fields: vec![],
                    }
                    .into_response();
                }
            }
        }
    };

    let cmd = BindNamespaceCommand {
        label: label.clone(),
        cwd_hash: Some(body.cwd_hash.clone()),
        dek_version: 1,
    };

    match cmd.execute(&ctx).await {
        Ok(output) => {
            // Enforce the per-namespace process allowlist (gap #6). This is the
            // primary chokepoint for MCP clients: ADR-0026 allows at most one
            // bind per session, so gating bind gates the whole session's
            // namespace access. Bind is idempotent (ADR-0026) — for an existing
            // namespace `execute` resolves it with no INSERT/audit, so denying
            // here has no side effect; a brand-new namespace has an empty
            // allowlist and is therefore allowed.
            if let Err(problem) = consumer_gate::check(&ctx, &output.namespace_id, &peer).await {
                return problem.into_response();
            }

            let resp = CreateSessionResponse {
                // Use the namespace_id as the session_id — there's a 1:1
                // mapping in Phase 6; a separate session table is Phase 6.B.
                session_id: output.namespace_id.inner().inner(),
                namespace_id: output.namespace_id.inner().inner(),
                namespace_label: output.label.to_string(),
                policy_profile: SecurityProfile::Balanced,
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `DELETE /v1/sessions/{session_id}`
///
/// Called by the MCP Adapter when the MCP client closes.
///
/// NOTE: Namespace bindings are persistent across sessions. This endpoint
/// acknowledges the close and clears any in-flight state (none in Phase 6).
/// A dedicated `UnbindNamespaceCommand` will be wired in Phase 6.B.
#[instrument(skip(_ctx))]
#[expect(
    clippy::used_underscore_binding,
    reason = "axum extractors accepted but intentionally unused in Phase 6.B stub"
)]
pub async fn close_session(
    State(_ctx): State<Arc<AppContext>>,
    Path(_session_id): Path<Uuid>,
) -> impl IntoResponse {
    // FIXME(F6.B): Wire to UnbindNamespaceCommand once implemented.
    // For now, respond with a 200 no-op acknowledging the close.
    let resp = CloseSessionResponse {
        closed: true,
        use_tokens_revoked: Some(0),
        tempfiles_scheduled_for_cleanup: Some(0),
    };
    (StatusCode::OK, Json(resp))
}
