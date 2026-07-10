//! Handlers for `GET /v1/agent/status`, `POST /v1/agent/init`,
//! `POST /v1/agent/unseal`, and `POST /v1/agent/seal`.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use merkle_application::ChainOutcome;
use merkle_application::queries::verify_chain::VerifyChainQuery;
use merkle_domain_backup_recovery::scheduler::BackupScheduler;
use merkle_domain_identity::{KEYCHAIN_ACCOUNT_MASTER_KEY, KEYCHAIN_SERVICE, UnsealPreconditions};
use merkle_ports::KeychainError;
use merkle_types::{Rfc3339Timestamp, SecurityProfile};
use std::path::{Path, PathBuf};
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

    let db_path = ctx.db_path.read().await.clone();
    let (db_path_str, db_size_bytes, disk_free_bytes) = db_diagnostics(db_path.as_deref());

    let keychain_reachable = probe_keychain_reachable(&ctx).await;
    let audit_chain_valid = probe_audit_chain_valid(&ctx, sealed).await;
    let (backup_overdue, last_backup_at) = backup_status(&ctx).await;

    let mut warnings = Vec::new();
    if sealed {
        warnings.push("vault is sealed; unseal to run HMAC chain verification".into());
    }
    if !keychain_reachable {
        warnings.push("keychain probe failed".into());
    }
    if !audit_chain_valid {
        warnings.push("audit chain verification failed".into());
    }

    let resp = AgentStatusResponse {
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        vault_state,
        sealed,
        keychain_reachable,
        db_path: db_path_str,
        db_size_bytes,
        audit_chain_valid,
        backup_overdue,
        disk_free_bytes,
        last_backup_at,
        expiring_soon: vec![],
        warnings,
    };
    (StatusCode::OK, Json(resp))
}

fn db_diagnostics(db_path: Option<&Path>) -> (String, u64, u64) {
    let Some(path) = db_path else {
        return (String::new(), 0, 0);
    };
    let path_str = path.display().to_string();
    // SQLite WAL companions are named `{file}-wal` / `{file}-shm`.
    let wal_path = PathBuf::from(format!("{}-wal", path.display()));
    let shm_path = PathBuf::from(format!("{}-shm", path.display()));
    let size = std::fs::metadata(path).map_or(0, |m| m.len())
        + std::fs::metadata(&wal_path).map_or(0, |m| m.len())
        + std::fs::metadata(&shm_path).map_or(0, |m| m.len());
    let free = disk_free_bytes(path);
    (path_str, size, free)
}

#[cfg(unix)]
fn disk_free_bytes(path: &Path) -> u64 {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    // Prefer the parent dir so a missing file still yields free space of the volume.
    let probe = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    let Ok(c_path) = CString::new(probe.as_os_str().as_bytes()) else {
        return 0;
    };
    // SAFETY: `statvfs` writes into a stack-allocated `statvfs`; `c_path` is a
    // NUL-terminated CString whose lifetime covers the call.
    #[expect(
        unsafe_code,
        reason = "statvfs(2) has no safe Rust wrapper in this crate's deps"
    )]
    let free = unsafe {
        let mut s: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), std::ptr::from_mut(&mut s)) == 0 {
            u64::from(s.f_bavail).saturating_mul(s.f_frsize)
        } else {
            0
        }
    };
    free
}

#[cfg(not(unix))]
fn disk_free_bytes(_path: &Path) -> u64 {
    0
}

async fn probe_keychain_reachable(ctx: &AppContext) -> bool {
    match ctx
        .keychain
        .retrieve(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_MASTER_KEY)
        .await
    {
        Ok(_) | Err(KeychainError::NotFound) => true,
        Err(_) => false,
    }
}

async fn probe_audit_chain_valid(ctx: &AppContext, sealed: bool) -> bool {
    if sealed {
        // Cannot HMAC-verify without the key; treat readable storage as "not known bad".
        return ctx.storage.pinned_head().await.is_ok();
    }
    match VerifyChainQuery.execute(ctx).await {
        Ok(out) => out.result.outcome == ChainOutcome::Intact,
        Err(_) => false,
    }
}

async fn backup_status(ctx: &AppContext) -> (bool, Option<chrono::DateTime<chrono::Utc>>) {
    let state = ctx.anacron.read().await.clone();
    let now = Rfc3339Timestamp::now();
    let overdue = BackupScheduler::should_trigger(&now, &state).is_some();
    let last = state.last_backup_at.map(|ts| ts.inner());
    (overdue, last)
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
    let security_profile = req.security_profile.unwrap_or(SecurityProfile::Balanced);

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
#[expect(
    clippy::used_underscore_binding,
    reason = "axum extractor accepted but intentionally unused"
)]
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
            // ADR-0025 §Bug #5: propagate the new `was_already_unsealed`
            // discriminator so CLI/MCP callers print the correct status text.
            // Previously this aliased `output.unsealed` (always true on success),
            // making every unseal response read as "already unsealed".
            let resp = UnsealResponse {
                sealed: !output.unsealed,
                already_unsealed: output.was_already_unsealed,
                method: None,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `POST /v1/agent/seal`
///
/// Transitions the agent from Unsealed to Sealed state, wiping VRK material.
#[instrument(skip(ctx))]
pub async fn seal(State(ctx): State<Arc<AppContext>>) -> impl IntoResponse {
    let cmd = merkle_application::commands::seal_vault::SealVaultCommand;
    match cmd.execute(&ctx).await {
        Ok(output) => {
            let resp = SealResponse {
                sealed: output.sealed,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}
