//! `DescribeSecretCommand` — read-only metadata fetch (no `PrivateBlob`).

use merkle_domain_secret_storage::Secret;
use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for describing a secret.
#[derive(Debug)]
pub struct DescribeSecretCommand {
    /// The namespace owning the secret.
    pub namespace_id: NamespaceId,

    /// The vault URI of the secret to describe.
    pub handle: Handle,
}

/// Output of `DescribeSecretCommand`.
#[derive(Debug)]
pub struct DescribeSecretOutput {
    /// Full secret aggregate (the driving adapter must strip `PrivateBlob`
    /// before returning to an untrusted caller).
    pub secret: Secret,
}

impl DescribeSecretCommand {
    /// Execute describe-secret.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault is not `Unsealed`.
    /// - [`AppError::NotFound`] — no secret found for the given handle.
    /// - [`AppError::Storage`] — storage query failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<DescribeSecretOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(handle = %self.handle, "describe_secret: fetching metadata");

        // Convert Handle to its storage key.
        let secret = ctx
            .storage
            .get_secret_by_handle(&self.handle)
            .await?
            .ok_or(AppError::NotFound)?;

        // Audit.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Describe,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .handle(self.handle.clone())
        .sensitivity(secret.sensitivity)
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        Ok(DescribeSecretOutput { secret })
    }
}
