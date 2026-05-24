//! Handler for `GET /v1/namespaces`.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::instrument;

use crate::{
    AppContext,
    dto::{ListNamespacesResponse, NamespaceDto},
    problem::app_error_to_problem,
};

/// `GET /v1/namespaces`
///
/// Returns the list of Namespaces that exist in the vault database.
#[instrument(skip(ctx))]
pub async fn list_namespaces(State(ctx): State<Arc<AppContext>>) -> impl IntoResponse {
    let query = merkle_application::queries::list_namespaces::ListNamespacesQuery::default();

    match query.execute(&ctx).await {
        Ok(output) => {
            let items: Vec<NamespaceDto> = output
                .namespaces
                .into_iter()
                .map(|ns| NamespaceDto {
                    // NamespaceId(UuidV7(Uuid)) — unwrap to uuid::Uuid
                    id: ns.id.inner().inner(),
                    label: ns.label.to_string(),
                    policy_profile: merkle_types::SecurityProfile::Balanced,
                    created_at: ns.created_at.inner(),
                    dek_version: ns.dek_version,
                    cwd_hash: ns.cwd_hash,
                    policy_id: ns.policy_id.map(|id| id.inner()),
                    secret_count: None,
                })
                .collect();
            let total = u32::try_from(items.len()).unwrap_or(u32::MAX);
            let resp = ListNamespacesResponse {
                items,
                total,
                next_cursor: None,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}
