//! `RestorePlanCommand` — generate a restore diff preview without applying changes.
//!
//! Verifies backup HMAC, decrypts with the master age identity, builds a
//! [`RestorePlan`] via [`RestorePlanner`], persists it, and returns it for
//! operator review. Preview does **not** append a successful restore audit.

use merkle_domain_backup_recovery::planner::RestorePlanner;
use merkle_domain_backup_recovery::restore_mode::RestoreMode;
use merkle_domain_backup_recovery::restore_plan::RestorePlan;
use merkle_ports::SecretFilter;
use merkle_types::{AuditOp, AuditOutcome, HmacSignature, NamespaceId, UuidV7};
use tracing::info;

use crate::backup_payload::BackupPlaintext;
use crate::backup_recipients::load_master_identity;
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
    /// The durable restore plan (persisted; keyed by `plan.id`).
    pub plan: RestorePlan,
    /// Secrets present only in the backup (pure adds).
    pub secrets_to_add: u32,
    /// Conflicting secrets the mode will take from the backup.
    pub secrets_to_overwrite: u32,
    /// Conflicting secrets the mode will keep local (skip backup).
    pub secrets_to_skip: u32,
}

impl RestorePlanCommand {
    /// Execute restore-plan (preview phase).
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::NotFound`] — backup not found for `backup_snapshot_id`.
    /// - [`AppError::BackupIntegrity`] — ciphertext HMAC mismatch.
    /// - [`AppError::Crypto`] — age decryption failed.
    /// - [`AppError::Storage`] — storage query or plan write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<RestorePlanOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(
            namespace = %self.namespace_id,
            backup_snapshot_id = %self.backup_snapshot_id,
            "restore_plan: computing restore diff"
        );

        let backups = ctx.storage.list_backups(&self.namespace_id).await?;
        let backup = backups
            .iter()
            .find(|b| b.snapshot_id == self.backup_snapshot_id)
            .ok_or(AppError::NotFound)?;

        let ciphertext = tokio::fs::read(&backup.artifact.path)
            .await
            .map_err(|e| AppError::Domain(format!("failed to read backup artifact: {e}")))?;

        let hmac_key = ctx.require_hmac_key().await?;
        if let Err(err) = verify_backup_hmac(&hmac_key, &ciphertext, &backup.hmac) {
            audit_restore_deny(ctx, self.namespace_id, &hmac_key, "backup_integrity_check_failed")
                .await?;
            return Err(err);
        }

        let identity = load_master_identity(ctx).await?;
        let plaintext = ctx.crypto.age_decrypt(&identity, &ciphertext)?;
        let payload = BackupPlaintext::decode(&plaintext).map_err(AppError::Domain)?;
        let backup_secrets = payload.secrets();

        let live_secrets = ctx
            .storage
            .list_secrets(&self.namespace_id, SecretFilter::default())
            .await?;

        let backup_side: Vec<(merkle_types::Handle, merkle_types::Rfc3339Timestamp)> =
            backup_secrets
                .iter()
                .map(|s| (s.handle.clone(), s.created_at))
                .collect();
        let live_side: Vec<(merkle_types::Handle, merkle_types::Rfc3339Timestamp)> = live_secrets
            .iter()
            .map(|s| (s.handle.clone(), s.created_at))
            .collect();

        let mut plan = RestorePlanner::plan(
            backup.snapshot_id,
            &backup_side,
            &live_side,
            self.mode,
        );
        plan.target_namespace = Some(self.namespace_id);

        let live_handles: std::collections::HashSet<_> =
            live_side.iter().map(|(h, _)| h.clone()).collect();
        let secrets_to_add = u32::try_from(
            backup_side
                .iter()
                .filter(|(h, _)| !live_handles.contains(h))
                .count(),
        )
        .unwrap_or(u32::MAX);

        use merkle_domain_backup_recovery::restore_plan::ConflictResolution;
        let mut secrets_to_overwrite = 0_u32;
        let mut secrets_to_skip = 0_u32;
        for c in &plan.conflicts {
            match c.resolution {
                ConflictResolution::NewestWinsBackup | ConflictResolution::PreserveBoth => {
                    secrets_to_overwrite = secrets_to_overwrite.saturating_add(1);
                }
                ConflictResolution::NewestWinsExisting => {
                    secrets_to_skip = secrets_to_skip.saturating_add(1);
                }
                ConflictResolution::Halt => {
                    secrets_to_skip = secrets_to_skip.saturating_add(1);
                }
            }
        }

        ctx.storage.put_restore_plan(&plan).await?;

        info!(
            plan_id = %plan.id,
            conflicts = plan.conflicts.len(),
            secrets_to_add,
            "restore_plan: plan generated and persisted"
        );

        Ok(RestorePlanOutput {
            plan,
            secrets_to_add,
            secrets_to_overwrite,
            secrets_to_skip,
        })
    }
}

/// Verify encrypt-then-MAC tag over backup ciphertext (ADR-0006).
pub(crate) fn verify_backup_hmac(
    hmac_key: &[u8; 32],
    ciphertext: &[u8],
    expected: &HmacSignature,
) -> Result<(), AppError> {
    let computed = HmacSignature::compute(hmac_key, ciphertext);
    if computed.ct_eq(expected) {
        Ok(())
    } else {
        Err(AppError::BackupIntegrity)
    }
}

async fn audit_restore_deny(
    ctx: &AppContext,
    namespace_id: NamespaceId,
    hmac_key: &[u8; 32],
    reason: &str,
) -> Result<(), AppError> {
    let params = merkle_domain_audit_compliance::AppendParams::new(
        AuditOp::Restore,
        AuditOutcome::Deny,
        namespace_id,
    )
    .caller_program("merkle-agent")
    .denial_reason(reason);
    crate::commands::unseal_vault::audit_commit(ctx, params, hmac_key).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_types::HmacSignature;

    #[test]
    fn matching_hmac_passes() {
        let key = [7u8; 32];
        let data = b"ciphertext-bytes";
        let tag = HmacSignature::compute(&key, data);
        assert!(verify_backup_hmac(&key, data, &tag).is_ok());
    }

    #[test]
    fn flipped_bit_fails_integrity() {
        let key = [7u8; 32];
        let data = b"ciphertext-bytes";
        let tag = HmacSignature::compute(&key, data);
        let mut bad = data.to_vec();
        bad[0] ^= 0xff;
        assert!(matches!(
            verify_backup_hmac(&key, &bad, &tag),
            Err(AppError::BackupIntegrity)
        ));
    }
}
