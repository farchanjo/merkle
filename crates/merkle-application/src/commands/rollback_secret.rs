//! `RollbackSecretCommand` — restore a historical secret version as a new active version.
//!
//! Rollback never re-activates a version in place: it copies the target blob
//! into a new `SecretVersion` via [`Secret::rollback_to`] (immutable history).
//! Every rollback requires operator slash-command confirmation.

use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;
use merkle_domain_secret_storage::RetentionPolicy;
use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for rolling a secret back to a historical version.
#[derive(Debug)]
pub struct RollbackSecretCommand {
    /// Namespace owning the secret.
    pub namespace_id: NamespaceId,

    /// Vault URI of the secret to roll back.
    pub handle: Handle,

    /// Historical `version_no` whose blob should become active again.
    pub target_version: u32,

    /// Operator confirmation — `slash_command` must be true for every rollback.
    pub operator_confirmation: OperatorConfirmation,
}

/// Output of `RollbackSecretCommand`.
#[derive(Debug)]
pub struct RollbackSecretOutput {
    /// Version number of the newly active (post-rollback) version.
    pub active_version: u32,
}

impl RollbackSecretCommand {
    /// Execute secret-version rollback.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::NotFound`] — no secret found for the handle.
    /// - [`AppError::PolicyDenied`] — missing slash-command confirmation.
    /// - [`AppError::Domain`] — target version missing or rotate invariant failed.
    /// - [`AppError::Storage`] — persistence or audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<RollbackSecretOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(
            handle = %self.handle,
            target = self.target_version,
            "rollback_secret: loading current secret"
        );

        let mut secret = ctx
            .storage
            .get_secret_by_handle(&self.handle)
            .await?
            .ok_or(AppError::NotFound)?;

        // All rollbacks require slash_command confirmation (policy gate).
        if !self.operator_confirmation.slash_command {
            let hmac_key = ctx.require_hmac_key().await?;
            let params = merkle_domain_audit_compliance::AppendParams::new(
                AuditOp::Rotate,
                AuditOutcome::Deny,
                self.namespace_id,
            )
            .handle(self.handle.clone())
            .sensitivity(secret.sensitivity)
            .denial_reason("operator confirmation required for secret rollback")
            .caller_program("merkle-agent");
            crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;
            return Err(AppError::PolicyDenied(
                "operator confirmation required for secret rollback".into(),
            ));
        }

        let retention = RetentionPolicy::new(3).map_err(|e| AppError::Domain(e.to_string()))?;
        let active_version = secret
            .rollback_to(self.target_version, &retention)
            .map_err(|e| AppError::Domain(e.to_string()))?
            .version_no;

        ctx.storage.put_secret(&secret).await?;

        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Rotate,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .handle(self.handle.clone())
        .sensitivity(secret.sensitivity)
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(
            handle = %self.handle,
            target = self.target_version,
            active = active_version,
            "rollback_secret: rolled back"
        );
        Ok(RollbackSecretOutput { active_version })
    }
}
