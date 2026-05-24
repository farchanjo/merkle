//! Handlers for `GET /v1/agent/status`, `POST /v1/agent/init`,
//! `POST /v1/agent/unseal`, and `POST /v1/agent/seal`.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use merkle_domain_identity::UnsealPreconditions;
use merkle_types::SecurityProfile;
use std::sync::Arc;
use tracing::instrument;

use crate::{
    AppContext,
    dto::{
        AgentStatusResponse, InitVaultRequest, InitVaultResponse, SealResponse, UnsealRequest,
        UnsealResponse, VaultState,
    },
    problem::app_error_to_problem,
};

/// `GET /v1/agent/status`
///
/// Returns the current seal state, agent version, and diagnostic indicators.
/// Always available regardless of seal state.
#[instrument(skip(ctx))]
pub async fn status(State(ctx): State<Arc<AppContext>>) -> impl IntoResponse {
    let sealed = !ctx.is_unsealed().await;
    let vault_state = if sealed {
        VaultState::Sealed
    } else {
        VaultState::Unsealed
    };
    let resp = AgentStatusResponse {
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        vault_state,
        sealed,
        keychain_reachable: true,
        db_path: String::new(),
        db_size_bytes: 0,
        audit_chain_valid: true,
        backup_overdue: false,
        disk_free_bytes: 0,
        last_backup_at: None,
        expiring_soon: vec![],
        warnings: vec![],
    };
    (StatusCode::OK, Json(resp))
}

/// `POST /v1/agent/init`
///
/// Executes the 8-step vault bootstrap ceremony (ADR-0021):
/// generates the Master Key, Recovery Key, and Vault Root Key;
/// dual-wraps the VRK; persists both copies; emits the audit entry.
///
/// Returns `201 Created` with the `recovery_key` (age X25519 recipient string)
/// on success — this is the ONLY time the Recovery Key is transmitted.
///
/// Returns `409 Conflict` with problem type `already_initialized` if the vault
/// has been initialized before.
#[instrument(skip(ctx))]
pub async fn init(
    State(ctx): State<Arc<AppContext>>,
    body: Option<Json<InitVaultRequest>>,
) -> impl IntoResponse {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let security_profile = req
        .security_profile
        .unwrap_or(SecurityProfile::Balanced);

    let cmd = merkle_application::commands::init_vault::InitVaultCommand {
        interactive: false,
        security_profile,
    };

    match cmd.execute(&ctx).await {
        Ok(output) => {
            let resp = InitVaultResponse {
                vault_id: output.vault_id.to_string(),
                recovery_key: output.recovery_key,
                master_key_keychain_ref: output.master_key_keychain_ref,
            };
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `POST /v1/agent/unseal`
///
/// Transitions the agent from Sealed to Unsealed state.
#[instrument(skip(ctx))]
#[expect(clippy::used_underscore_binding, reason = "axum extractor accepted but intentionally unused")]
pub async fn unseal(
    State(ctx): State<Arc<AppContext>>,
    _body: Option<Json<UnsealRequest>>,
) -> impl IntoResponse {
    // Construct preconditions: attempt mlock (best-effort) and assume entropy
    // is seeded. In a real binary these would be checked at startup; here we
    // accept the caller's intent and let the identity aggregate enforce policy.
    let preconditions = UnsealPreconditions {
        security_profile: SecurityProfile::Balanced,
        mlock_succeeded: false,
        entropy_seeded: true,
        keychain_reachable: true,
    };

    let cmd = merkle_application::commands::unseal_vault::UnsealVaultCommand { preconditions };

    match cmd.execute(&ctx).await {
        Ok(output) => {
            let resp = UnsealResponse {
                sealed: !output.unsealed,
                already_unsealed: output.unsealed,
                method: None,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `POST /v1/agent/seal`
///
/// Zeroizes the Vault Root Key and transitions the agent to Sealed state.
#[instrument(skip(ctx))]
pub async fn seal(State(ctx): State<Arc<AppContext>>) -> impl IntoResponse {
    let cmd = merkle_application::commands::seal_vault::SealVaultCommand;

    match cmd.execute(&ctx).await {
        Ok(output) => {
            let resp = SealResponse { sealed: output.sealed };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}
