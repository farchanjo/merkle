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

/// Map HTTP query params → domain `AuditQuery` filter.
///
/// The `op` and `outcome` filters are parsed from their string query values via
/// the [`AuditOp`](merkle_types::AuditOp) / [`AuditOutcome`](merkle_types::AuditOutcome)
/// `FromStr` impls. Previously both were hardcoded to `None`, making the
/// documented `op` and `outcome` filters silent no-ops (BUG-13).
fn to_domain_query(params: &AuditQuery) -> DomainAuditQuery {
    DomainAuditQuery {
        op: params.op.as_deref().and_then(|s| s.parse().ok()),
        outcome: params.outcome.as_deref().and_then(|s| s.parse().ok()),
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
    }
}

/// `GET /v1/audit`
///
/// Returns audit entries matching the supplied filter criteria.
#[instrument(skip(ctx))]
pub async fn query_audit(
    State(ctx): State<Arc<AppContext>>,
    Query(params): Query<AuditQuery>,
) -> impl IntoResponse {
    let filter = to_domain_query(&params);

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

#[cfg(test)]
mod tests {
    use super::{AuditQuery, to_domain_query};
    use merkle_types::{AuditOp, AuditOutcome};

    /// BUG-13: `op` and `outcome` query params must be parsed and applied, not
    /// silently dropped to `None`.
    #[test]
    fn parses_op_and_outcome_filters() {
        let params = AuditQuery {
            handle: None,
            op: Some("rotate".into()),
            since: None,
            until: None,
            session_id: None,
            outcome: Some("deny".into()),
            verify_chain: false,
            limit: 50,
        };

        let filter = to_domain_query(&params);

        assert_eq!(filter.op, Some(AuditOp::Rotate));
        assert_eq!(filter.outcome, Some(AuditOutcome::Deny));
    }

    /// Unparseable op/outcome degrade to no-filter rather than erroring.
    #[test]
    fn unknown_op_outcome_become_none() {
        let params = AuditQuery {
            op: Some("not-an-op".into()),
            outcome: Some("maybe".into()),
            ..AuditQuery::default()
        };

        let filter = to_domain_query(&params);

        assert_eq!(filter.op, None);
        assert_eq!(filter.outcome, None);
    }
}
