//! `RestorePlanCommand` — generate a restore diff preview without applying changes.
//!
//! Calls [`RestorePlanner::plan`] to produce a [`RestorePlan`] describing
//! conflicts between the stored backup and the live vault state. The plan is
//! returned to the operator for inspection before execution via
//! [`super::execute_restore::ExecuteRestoreCommand`].

use merkle_domain_backup_recovery::planner::RestorePlanner;
use merkle_domain_backup_recovery::restore_mode::RestoreMode;
use merkle_domain_backup_recovery::restore_plan::RestorePlan;
use merkle_ports::SecretFilter;
use merkle_types::{AuditOp, AuditOutcome, NamespaceId, UuidV7};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for creating a restore plan.
#[derive(Debug)]
pub struct RestorePlanCommand {
    /// Namespace to restore into.
    pub namespace_id: NamespaceId,
    /// UUIDv7 snapshot_id of the backup record to plan against.
    pub backup_snapshot_id: UuidV7,
    /// Conflict-resolution strategy.
    pub mode: RestoreMode,
}

/// Output of `RestorePlanCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RestorePlanOutput {
    /// The generated restore plan.
    pub plan: RestorePlan,
}

impl RestorePlanCommand {
    /// Execute restore-plan (preview phase).
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::NotFound`] — backup not found for `backup_snapshot_id`.
    /// - [`AppError::Storage`] — storage query or audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<RestorePlanOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(
            namespace = %self.namespace_id,
            backup_snapshot_id = %self.backup_snapshot_id,
            "restore_plan: computing restore diff"
        );

        // Load backup records for this namespace and find the requested one.
        let backups = ctx.storage.list_backups(&self.namespace_id).await?;
        let backup = backups
            .iter()
            .find(|b| b.snapshot_id == self.backup_snapshot_id)
            .ok_or(AppError::NotFound)?;

        // Load live vault secrets to detect conflicts.
        let live_secrets = ctx
            .storage
            .list_secrets(&self.namespace_id, SecretFilter::default())
            .await?;

        // Phase 5: backup artifact contains aggregate metadata only (secret_count,
        // created_at) without per-secret handle enumeration. The planner receives
        // an empty backup-side slice — conflicts are detected from the live side.
        // Per-handle backup diffs are a Phase 6 concern (requires iterating the
        // age-encrypted artifact).
        let backup_secrets: Vec<(merkle_types::Handle, merkle_types::Rfc3339Timestamp)> = Vec::new();

        let current_secrets: Vec<(merkle_types::Handle, merkle_types::Rfc3339Timestamp)> =
            live_secrets
                .iter()
                .map(|s| (s.handle.clone(), s.created_at))
                .collect();

        let plan = RestorePlanner::plan(
            backup.snapshot_id,
            &backup_secrets,
            &current_secrets,
            self.mode,
        );

        // Audit: op=restore (plan phase).
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Restore,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        drop(log);
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!(plan_id = %plan.id, conflicts = plan.conflicts.len(), "restore_plan: plan generated");
        Ok(RestorePlanOutput { plan })
    }
}
