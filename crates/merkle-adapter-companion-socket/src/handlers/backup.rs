//! Handlers for Backup and Recovery endpoints:
//!
//! - `POST /v1/backup`
//! - `GET  /v1/backup/snapshots`
//! - `POST /v1/backup/restore-plan`
//! - `POST /v1/backup/restore`

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use merkle_application::{
    commands::{
        execute_restore::ExecuteRestoreCommand, restore_plan::RestorePlanCommand,
        trigger_backup::TriggerBackupCommand,
    },
    queries::list_backups::ListBackupsQuery,
};
use merkle_domain_backup_recovery::{
    restore_mode::RestoreMode as DomainRestoreMode, restore_plan::ConflictResolution,
    trigger::BackupTrigger as DomainBackupTrigger,
};
use merkle_ports::AgeIdentity;
use merkle_types::{NamespaceId, UuidV7};
use std::{path::PathBuf, sync::Arc};
use tracing::instrument;

use crate::{
    AppContext,
    dto::{
        BackupSnapshotDto, BackupTrigger as DtoBackupTrigger, CreateRestorePlanRequest,
        ExecuteRestoreRequest, ExecuteRestoreResponse, ListSnapshotsParams, ListSnapshotsResponse,
        RestoreConflictDto, RestoreMode as DtoRestoreMode, RestorePlanResponse,
        TriggerBackupRequest,
    },
    problem::{Problem, ProblemType, app_error_to_problem, not_implemented},
};

/// Derive a deterministic namespace ID used as the default backup namespace.
///
/// Phase 6: A single-namespace vault is assumed for backup operations. When
/// multiple namespaces are present the caller should supply an explicit
/// namespace_id query parameter (future extension).
async fn default_namespace_id(ctx: &AppContext) -> Option<NamespaceId> {
    // Use the ListNamespacesQuery to get any namespace; take the first one.
    let q = merkle_application::queries::list_namespaces::ListNamespacesQuery::default();
    q.execute(ctx)
        .await
        .ok()
        .and_then(|o| o.namespaces.into_iter().next())
        .map(|ns| ns.id)
}

/// Backup and restore deliberately fail closed until their two-recipient key
/// provisioning and durable restore-plan storage are designed and wired.
///
/// The Master Key is symmetric and no corresponding `age` recipient exists in
/// the current identity model.  Pretending the recovery recipient is both
/// recipients produced backups that no documented recovery path could prove.
/// Likewise, restore plans are not persisted, so an opaque plan id cannot be
/// resolved safely after a request boundary.
fn backup_recovery_available() -> bool {
    false
}

/// `POST /v1/backup`
///
/// Initiates an on-demand encrypted backup of the entire vault state.
#[instrument(skip(ctx))]
pub async fn trigger_backup(
    State(ctx): State<Arc<AppContext>>,
    body: Option<Json<TriggerBackupRequest>>,
) -> impl IntoResponse {
    if !backup_recovery_available() {
        return not_implemented(
            "Backup is unavailable until distinct master and recovery age recipients are configured.",
        )
        .into_response();
    }

    // Resolve namespace to back up.
    let Some(namespace_id) = default_namespace_id(&ctx).await else {
        return not_implemented("trigger_backup: no namespace found; create a session first.")
            .into_response();
    };

    // Write backup artifact to a temp file in the system temp dir.
    let artifact_path = PathBuf::from(format!("/tmp/merkle-backup-{}.age", uuid::Uuid::now_v7()));

    let _note = body.as_ref().and_then(|b| b.note.clone());

    // Encrypt the backup to the vault's real recovery recipient (the age public
    // key held in VaultIdentity), so only the holder of the offline recovery
    // private key can ever decrypt it. The master key is symmetric and is not
    // an age recipient, so the recovery key is the sole recipient.
    let recovery_recipient = {
        let identity = ctx.identity.read().await;
        identity.recovery_pubkey().identity_pubkey().to_owned()
    };

    // Refuse to back up if the identity still carries the bootstrap placeholder:
    // a backup encrypted to a guessable / null recipient is worse than no
    // backup at all.
    if recovery_recipient.is_empty() || recovery_recipient.contains("placeholder") {
        return Problem {
            kind: ProblemType::BackupFailed,
            title: "Vault recovery key not configured".into(),
            status: 409,
            detail: "The vault has no real recovery key; run the init ceremony \
                     before creating a backup. Refusing to encrypt a backup to a \
                     placeholder recipient."
                .into(),
            instance: None,
            hint: Some("Initialise the vault with `merkle init`.".into()),
            fields: vec![],
        }
        .into_response();
    }

    let cmd = TriggerBackupCommand {
        namespace_id,
        trigger: DomainBackupTrigger::Manual,
        master_pubkey_recipient: recovery_recipient.clone(),
        recovery_pubkey_recipient: recovery_recipient,
        output_path: artifact_path.clone(),
    };

    match cmd.execute(&ctx).await {
        Ok(output) => {
            let b = &output.backup;
            let snap = BackupSnapshotDto {
                filename: artifact_path
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
                created_at: b.created_at.inner(),
                size_bytes: b.size_bytes,
                namespace_count: Some(1),
                secret_count: Some(b.secret_count),
                trigger: Some(DtoBackupTrigger::Manual),
            };
            (StatusCode::ACCEPTED, Json(snap)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `GET /v1/backup/snapshots`
///
/// Lists available backup snapshot metadata.
#[instrument(skip(ctx))]
pub async fn list_snapshots(
    State(ctx): State<Arc<AppContext>>,
    Query(params): Query<ListSnapshotsParams>,
) -> impl IntoResponse {
    let Some(namespace_id) = default_namespace_id(&ctx).await else {
        // No namespace yet — return empty list.
        return (
            StatusCode::OK,
            Json(ListSnapshotsResponse {
                snapshots: vec![],
                next_cursor: None,
            }),
        )
            .into_response();
    };

    let query = ListBackupsQuery { namespace_id };

    match query.execute(&ctx).await {
        Ok(output) => {
            let limit = params.limit as usize;
            let snapshots: Vec<BackupSnapshotDto> = output
                .backups
                .iter()
                .take(limit)
                .map(|b| BackupSnapshotDto {
                    filename: b.artifact.path.file_name().map_or_else(
                        || b.snapshot_id.to_string(),
                        |n| n.to_string_lossy().into_owned(),
                    ),
                    created_at: b.created_at.inner(),
                    size_bytes: b.size_bytes,
                    namespace_count: Some(1),
                    secret_count: Some(b.secret_count),
                    trigger: Some(match b.trigger {
                        DomainBackupTrigger::Manual => DtoBackupTrigger::Manual,
                        DomainBackupTrigger::ChangeTriggered => DtoBackupTrigger::ChangeTriggered,
                        DomainBackupTrigger::IdleTriggered => DtoBackupTrigger::IdleTriggered,
                        DomainBackupTrigger::AnacronTriggered => DtoBackupTrigger::AnacronTriggered,
                    }),
                })
                .collect();
            (
                StatusCode::OK,
                Json(ListSnapshotsResponse {
                    snapshots,
                    next_cursor: None,
                }),
            )
                .into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// Map a `ConflictResolution` domain value to the DTO string representation.
fn conflict_resolution_str(r: ConflictResolution) -> &'static str {
    match r {
        ConflictResolution::NewestWinsExisting => "newest_wins_existing",
        ConflictResolution::NewestWinsBackup => "newest_wins_backup",
        ConflictResolution::Halt => "halt",
        ConflictResolution::PreserveBoth => "preserve_both",
    }
}

/// `POST /v1/backup/restore-plan`
///
/// Validates a backup file and generates a restore plan preview.
#[instrument(skip(ctx))]
pub async fn create_restore_plan(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<CreateRestorePlanRequest>,
) -> impl IntoResponse {
    if !backup_recovery_available() {
        return not_implemented(
            "Restore planning is unavailable until encrypted artifacts and durable restore plans are safely configured.",
        )
        .into_response();
    }

    let Some(namespace_id) = default_namespace_id(&ctx).await else {
        return Problem {
            kind: ProblemType::NamespaceNotFound,
            title: "No namespace found".into(),
            status: 404,
            detail: "No namespace exists in this vault. Create a session first.".into(),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    };

    // The snapshot filename is used to look up the backup record.
    // We find the backup whose artifact path ends with the requested filename.
    let list_q = ListBackupsQuery { namespace_id };
    let backups = match list_q.execute(&ctx).await {
        Ok(o) => o.backups,
        Err(err) => return app_error_to_problem(err).into_response(),
    };

    let backup = backups.iter().find(|b| {
        b.artifact
            .path
            .file_name()
            .is_some_and(|n| n.to_string_lossy() == body.snapshot_filename.as_str())
            || b.snapshot_id.to_string() == body.snapshot_filename
    });

    let Some(found_backup) = backup else {
        return Problem {
            kind: ProblemType::HandleNotFound,
            title: "Snapshot not found".into(),
            status: 404,
            detail: format!(
                "No backup with filename '{}' found.",
                body.snapshot_filename
            ),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    };
    let backup_snapshot_id: UuidV7 = found_backup.snapshot_id;

    let domain_mode = match body.mode {
        DtoRestoreMode::Overwrite => DomainRestoreMode::NewestWinsBackup,
        DtoRestoreMode::Merge => DomainRestoreMode::MergePreserveBoth,
        DtoRestoreMode::NewestWins => DomainRestoreMode::NewestWinsExisting,
    };

    let cmd = RestorePlanCommand {
        namespace_id,
        backup_snapshot_id,
        mode: domain_mode,
    };

    match cmd.execute(&ctx).await {
        Ok(output) => {
            let plan = &output.plan;
            let conflicts: Vec<RestoreConflictDto> = plan
                .conflicts
                .iter()
                .map(|c| RestoreConflictDto {
                    handle: c.handle.clone(),
                    resolution: conflict_resolution_str(c.resolution).into(),
                })
                .collect();
            let resp = RestorePlanResponse {
                plan_id: plan.id.to_string(),
                mode: body.mode,
                snapshot_filename: body.snapshot_filename,
                namespaces_to_add: 0,
                namespaces_to_skip: 0,
                secrets_to_add: 0,
                secrets_to_overwrite: 0,
                secrets_to_skip: u32::try_from(plan.conflicts.len()).unwrap_or(0),
                conflicts,
                expires_at: plan.expires_at.inner(),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

/// `POST /v1/backup/restore`
///
/// Applies a previously created restore plan.
#[instrument(skip(ctx))]
pub async fn execute_restore(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<ExecuteRestoreRequest>,
) -> impl IntoResponse {
    if !backup_recovery_available() {
        return not_implemented(
            "Restore is unavailable until a durable, verified restore-plan capability is configured.",
        )
        .into_response();
    }

    // Gate: both operator confirmation flags required for restore.
    if !body.operator_confirmation.slash_command || !body.operator_confirmation.oob_ack {
        return Problem {
            kind: ProblemType::OperatorConfirmationRequired,
            title: "Operator confirmation required".into(),
            status: 403,
            detail:
                "Both operator_confirmation.slash_command and oob_ack must be true for restore."
                    .into(),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    }

    let Some(namespace_id) = default_namespace_id(&ctx).await else {
        return Problem {
            kind: ProblemType::NamespaceNotFound,
            title: "No namespace found".into(),
            status: 404,
            detail: "No namespace exists in this vault.".into(),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    };

    // The plan_id is the snapshot_id from the restore plan.
    let Ok(backup_snapshot_id) = body.plan_id.parse::<UuidV7>() else {
        return Problem {
            kind: ProblemType::RestorePlanExpired,
            title: "Invalid plan ID".into(),
            status: 400,
            detail: format!("'{}' is not a valid plan_id (UUIDv7).", body.plan_id),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    };

    // Use a placeholder age identity for Phase 6.
    // FIXME(F6.C): Load the real age identity from VaultIdentity or from the
    // request recovery_key_path once key management is wired.
    let age_identity = AgeIdentity("AGE-SECRET-KEY-1PLACEHOLDER".into());

    let cmd = ExecuteRestoreCommand {
        namespace_id,
        backup_snapshot_id,
        age_identity,
    };

    match cmd.execute(&ctx).await {
        Ok(output) => {
            let resp = ExecuteRestoreResponse {
                restored: true,
                secrets_restored: output.secrets_restored,
                namespaces_restored: 1,
                restored_at: Some(chrono::Utc::now()),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}
