//! Handler for the diagnostics endpoint:
//!
//! - `GET /v1/agent/doctor`
//!
//! Orchestrates the `DoctorQuery` from the application layer and adapts the
//! output to the Companion Socket `DoctorResponse` DTO. Each `DoctorCheckResult`
//! is mapped to `DoctorCheck` with a synthetic `duration_ms` field (timing is
//! not instrumented at the application layer in Phase 6; the field is set to 0
//! and will be populated once per-check wall-clock timing is added).

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use merkle_application::queries::doctor::DoctorQuery;
use std::sync::Arc;
use tracing::instrument;

use crate::{
    AppContext,
    dto::{DoctorCheck, DoctorResponse},
    problem::app_error_to_problem,
};

/// `GET /v1/agent/doctor`
///
/// Runs internal health checks and returns a structured summary. All checks
/// must pass for `overall` to be `"healthy"`. Any single failure sets
/// `overall` to `"unhealthy"`.
///
/// Available while sealed (sealed-safe checks) and unsealed (full suite
/// including HMAC chain verification). The response intentionally avoids
/// key material and audit entry hashes.
#[instrument(skip(ctx))]
pub async fn doctor(State(ctx): State<Arc<AppContext>>) -> impl IntoResponse {
    match DoctorQuery.execute(&ctx).await {
        Ok(out) => {
            let checks: Vec<DoctorCheck> = out
                .checks
                .iter()
                .map(|c| DoctorCheck {
                    name: c.name.clone(),
                    status: if c.ok { "pass".into() } else { "fail".into() },
                    message: c.detail.clone(),
                    // Phase 6: timing not yet instrumented in DoctorQuery.
                    duration_ms: 0,
                })
                .collect();

            let overall = if out.all_ok { "healthy" } else { "unhealthy" }.to_owned();

            (StatusCode::OK, Json(DoctorResponse { checks, overall })).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}
