//! `DeleteSecretCommand` — hard-delete a secret by its handle.
//!
//! Policy: secrets with `Sensitivity::Critical` require `operator_confirmation`
//! (`slash_command == true`) before deletion. All deletes are audited.

use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;
use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId, Sensitivity};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for deleting a secret.
#[derive(Debug)]
pub struct DeleteSecretCommand {
    /// Namespace owning the secret.
    pub namespace_id: NamespaceId,
    /// Vault URI of the secret to delete.
    pub handle: Handle,
    /// Two-flag operator confirmation — required for high-sensitivity deletes.
    pub operator_confirmation: OperatorConfirmation,
}

/// Output of `DeleteSecretCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DeleteSecretOutput {
    /// The vault URI that was deleted.
    pub handle: Handle,
}

impl DeleteSecretCommand {
    /// Execute delete-secret.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::NotFound`] — secret not found for the handle.
    /// - [`AppError::PolicyDenied`] — high-sensitivity delete without slash_command.
    /// - [`AppError::Storage`] — storage delete or audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<DeleteSecretOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(handle = %self.handle, "delete_secret: resolving secret");

        // Load the secret to obtain its id and sensitivity.
        let secret = ctx
            .storage
            .get_secret_by_handle(&self.handle)
            .await?
            .ok_or(AppError::NotFound)?;

        // Policy gate: High sensitivity requires slash_command confirmation.
        // NOTE: `Sensitivity::Critical` was removed from the enum (only Low/Medium/High exist).
        // Using `Sensitivity::High` as the threshold per the doc-comment intent.
        if secret.sensitivity >= Sensitivity::High && !self.operator_confirmation.slash_command {
            // BUG-06: persist-then-advance atomically (see `audit_commit`).
            let hmac_key = ctx.require_hmac_key().await?;
            let params = merkle_domain_audit_compliance::AppendParams::new(
                AuditOp::Delete,
                AuditOutcome::Deny,
                self.namespace_id,
            )
            .handle(self.handle.clone())
            .sensitivity(secret.sensitivity)
            .denial_reason("operator confirmation required for critical-sensitivity delete")
            .caller_program("merkle-agent");
            crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;
            return Err(AppError::PolicyDenied(
                "operator confirmation required for critical-sensitivity delete".into(),
            ));
        }

        // Hard-delete from storage.
        ctx.storage.delete_secret(&secret.id).await?;

        // Audit success (BUG-06: persist-then-advance atomically).
        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Delete,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .handle(self.handle.clone())
        .sensitivity(secret.sensitivity)
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;
        ctx.record_vault_change().await;

        info!(handle = %self.handle, "delete_secret: secret deleted");
        Ok(DeleteSecretOutput {
            handle: self.handle.clone(),
        })
    }
}
