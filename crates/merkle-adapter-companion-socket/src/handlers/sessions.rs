//! Handlers for session lease endpoints:
//!
//! - `POST   /v1/sessions`
//! - `DELETE /v1/sessions/{session_id}`
//!
//! Sessions are backed by `BindNamespaceCommand`. Close clears in-memory
//! session state (use-tokens, tempfiles, port-forwards) without deleting the
//! persistent namespace binding.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use merkle_application::commands::bind_namespace::BindNamespaceCommand;
use merkle_types::{SecurityProfile, UuidV7};
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
    let raw_label = body
        .namespace_label
        .as_deref()
        .map_or_else(|| body.cwd_hash_slug(), str::to_owned);

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
            if let Err(problem) = consumer_gate::check(&ctx, &output.namespace_id, &peer).await {
                return problem.into_response();
            }

            let resp = CreateSessionResponse {
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
/// Clears in-memory session hygiene (use-tokens, tempfiles, port-forwards).
/// Namespace bindings remain persistent.
#[instrument(skip(ctx))]
pub async fn close_session(
    State(ctx): State<Arc<AppContext>>,
    Path(session_id): Path<Uuid>,
) -> impl IntoResponse {
    let sid = session_id
        .to_string()
        .parse::<UuidV7>()
        .unwrap_or_else(|_| UuidV7::new());
    let (use_tokens_revoked, tempfiles_scheduled_for_cleanup) =
        ctx.close_session_state(&sid).await;
    let resp = CloseSessionResponse {
        closed: true,
        use_tokens_revoked: Some(use_tokens_revoked),
        tempfiles_scheduled_for_cleanup: Some(tempfiles_scheduled_for_cleanup),
    };
    (StatusCode::OK, Json(resp))
}
