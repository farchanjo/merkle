//! `ExecuteRestoreCommand` — apply a previewed durable restore plan.
//!
//! Loads the plan by id, enforces expiry/applied guards, re-verifies backup
//! HMAC, decrypts with the master age identity, and upserts secrets according
//! to the plan mode. Audits `op=restore` allow/deny.

use merkle_domain_backup_recovery::restore_plan::ConflictResolution;
use merkle_domain_secret_storage::Secret;
use merkle_ports::SecretFilter;
use merkle_types::{AuditOp, AuditOutcome, NamespaceId, Rfc3339Timestamp, UuidV7};
use tracing::info;

use crate::backup_payload::BackupPlaintext;
use crate::backup_recipients::load_master_identity;
use crate::commands::restore_plan::verify_backup_hmac;
use crate::{AppContext, AppError};

/// Input for executing a restore.
#[derive(Debug)]
pub struct ExecuteRestoreCommand {
    /// Durable plan id returned by restore-plan (not the backup snapshot id).
    pub plan_id: UuidV7,
}

/// Output of `ExecuteRestoreCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ExecuteRestoreOutput {
    /// Number of secrets successfully written by this apply.
    pub secrets_restored: u32,
    /// Namespace the plan targeted.
    pub namespace_id: NamespaceId,
}

impl ExecuteRestoreCommand {
    /// Execute a restore operation.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::NotFound`] — plan or backup missing.
    /// - [`AppError::RestorePlanExpired`] — plan TTL elapsed.
    /// - [`AppError::RestorePlanAlreadyApplied`] — plan already applied.
    /// - [`AppError::BackupIntegrity`] — ciphertext HMAC mismatch.
    /// - [`AppError::Crypto`] — age decryption failed.
    /// - [`AppError::Storage`] — secret write or audit failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<ExecuteRestoreOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(plan_id = %self.plan_id, "execute_restore: starting restore");

        let plan = ctx
            .storage
            .get_restore_plan(&self.plan_id)
            .await?
            .ok_or(AppError::NotFound)?;

        if plan.is_expired() {
            return Err(AppError::RestorePlanExpired);
        }

        if ctx
            .storage
            .restore_plan_applied_at(&self.plan_id)
            .await?
            .is_some()
        {
            return Err(AppError::RestorePlanAlreadyApplied);
        }

        if plan.has_halt_conflict() {
            return Err(AppError::InvalidInput(
                "restore plan has halt conflicts; refuse apply".into(),
            ));
        }

        let namespace_id = plan.target_namespace.ok_or_else(|| {
            AppError::Domain("restore plan missing target_namespace".into())
        })?;

        let backups = ctx.storage.list_backups(&namespace_id).await?;
        let backup = backups
            .iter()
            .find(|b| b.snapshot_id == plan.source_backup_id)
            .ok_or(AppError::NotFound)?;

        let ciphertext = tokio::fs::read(&backup.artifact.path)
            .await
            .map_err(|e| AppError::Domain(format!("failed to read backup artifact: {e}")))?;

        let hmac_key = ctx.require_hmac_key().await?;
        if let Err(err) = verify_backup_hmac(&hmac_key, &ciphertext, &backup.hmac) {
            let params = merkle_domain_audit_compliance::AppendParams::new(
                AuditOp::Restore,
                AuditOutcome::Deny,
                namespace_id,
            )
            .caller_program("merkle-agent")
            .denial_reason("backup_integrity_check_failed");
            crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;
            return Err(err);
        }

        let identity = load_master_identity(ctx).await?;
        let plaintext = ctx.crypto.age_decrypt(&identity, &ciphertext)?;
        let payload = BackupPlaintext::decode(&plaintext).map_err(AppError::Domain)?;
        let backup_secrets = payload.secrets().to_vec();

        let live_secrets = ctx
            .storage
            .list_secrets(&namespace_id, SecretFilter::default())
            .await?;
        let live_by_handle: std::collections::HashMap<_, _> = live_secrets
            .into_iter()
            .map(|s| (s.handle.clone(), s))
            .collect();

        let conflict_by_handle: std::collections::HashMap<_, _> = plan
            .conflicts
            .iter()
            .map(|c| (c.handle.clone(), c.resolution))
            .collect();

        let mut secrets_restored = 0_u32;

        for secret in backup_secrets {
            let handle = secret.handle.clone();
            match conflict_by_handle.get(&handle) {
                None => {
                    // Pure add (or local missing) — always write.
                    ctx.storage.put_secret(&secret).await?;
                    secrets_restored = secrets_restored.saturating_add(1);
                }
                Some(ConflictResolution::NewestWinsBackup) => {
                    ctx.storage.put_secret(&secret).await?;
                    secrets_restored = secrets_restored.saturating_add(1);
                }
                Some(ConflictResolution::NewestWinsExisting) => {
                    // Keep local — no write.
                }
                Some(ConflictResolution::PreserveBoth) => {
                    // Keep local; write backup under a suffixed handle name if possible.
                    // Fallback: skip when suffix construction fails.
                    if let Some(suffixed) = suffix_secret_handle(secret) {
                        if !live_by_handle.contains_key(&suffixed.handle) {
                            ctx.storage.put_secret(&suffixed).await?;
                            secrets_restored = secrets_restored.saturating_add(1);
                        }
                    }
                }
                Some(ConflictResolution::Halt) => {
                    // Guarded above; unreachable for valid plans.
                }
            }
        }

        let applied_at = Rfc3339Timestamp::now();
        ctx.storage
            .mark_restore_plan_applied(&self.plan_id, &applied_at)
            .await?;

        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Restore,
            AuditOutcome::Allow,
            namespace_id,
        )
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(
            plan_id = %self.plan_id,
            secrets_restored,
            "execute_restore: complete"
        );

        Ok(ExecuteRestoreOutput {
            secrets_restored,
            namespace_id,
        })
    }
}

/// Attempt to place a merge copy under `name-restored` within the same handle path.
fn suffix_secret_handle(secret: Secret) -> Option<Secret> {
    // Handles are vault://ns/cat/name — append suffix to the name segment.
    let handle_str = secret.handle.to_string();
    let suffixed = format!("{handle_str}-restored");
    let new_handle: merkle_types::Handle = suffixed.parse().ok()?;
    // Secret fields are mostly public; handle is public. Reconstruct via serde
    // round-trip so private version fields stay intact.
    let mut json = serde_json::to_value(&secret).ok()?;
    json["handle"] = serde_json::Value::String(new_handle.to_string());
    serde_json::from_value(json).ok()
}
