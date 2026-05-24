//! Handler for `GET /v1/audit`.

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use merkle_application::queries::query_audit::QueryAuditQuery;
use merkle_domain_audit_compliance::AuditQuery as DomainAuditQuery;
use std::sync::Arc;
use tracing::instrument;

use crate::{
    AppContext,
    dto::{AuditEntryDto, AuditQuery, AuditResponse},
    problem::app_error_to_problem,
};

/// `GET /v1/audit`
///
/// Returns audit entries matching the supplied filter criteria.
#[instrument(skip(ctx))]
pub async fn query_audit(
    State(ctx): State<Arc<AppContext>>,
    Query(params): Query<AuditQuery>,
) -> impl IntoResponse {
    // Map HTTP query params → domain AuditQuery filter.
    let filter = DomainAuditQuery {
        op: None, // string→enum parse requires AuditOp FromStr; leave as no-filter for now
        outcome: None,
        namespace_id: None,
        handle: params.handle.as_deref().and_then(|h| h.parse().ok()),
        sensitivity: None,
        from: params
            .since
            .map(|dt| merkle_types::Rfc3339Timestamp::try_from(dt.to_rfc3339().as_str()))
            .transpose()
            .ok()
            .flatten(),
        to: params
            .until
            .map(|dt| merkle_types::Rfc3339Timestamp::try_from(dt.to_rfc3339().as_str()))
            .transpose()
            .ok()
            .flatten(),
        limit: Some(params.limit),
    };

    let query = QueryAuditQuery {
        filter,
        verify_chain: params.verify_chain,
    };

    match query.execute(&ctx).await {
        Ok(output) => {
            let entries: Vec<AuditEntryDto> = output
                .entries
                .iter()
                .map(|e| AuditEntryDto {
                    id: e.id.inner().inner(),
                    ts: e.ts.inner(),
                    namespace_id: e.namespace_id.inner().inner(),
                    op: e.op.to_string(),
                    handle: e.handle.clone(),
                    purpose: None,
                    outcome: e.outcome.to_string(),
                    denial_reason: e.denial_reason.as_ref().map(ToString::to_string),
                    // session_id is not stored in AuditEntry; use nil UUID as placeholder.
                    session_id: uuid::Uuid::nil(),
                    caller_pid: None,
                    caller_program: e.caller_program.clone(),
                    seq: Some(e.seq),
                    note: None,
                    current_hash: e.current_hash.to_string(),
                    prev_hash: e.prev_hash.as_ref().map(ToString::to_string),
                    hmac: None,
                })
                .collect();
            let total = u32::try_from(entries.len()).unwrap_or(u32::MAX);
            (
                StatusCode::OK,
                Json(AuditResponse {
                    entries,
                    total,
                    chain_valid: output.chain_valid,
                }),
            )
                .into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}
