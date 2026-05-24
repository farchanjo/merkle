//! `BindNamespaceCommand` — create or bind a namespace to a working directory.

use merkle_domain_secret_storage::namespace::Namespace as NsDomain;
use merkle_types::{AuditOp, AuditOutcome, NamespaceId, NamespaceLabel};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for binding a namespace.
#[derive(Debug)]
pub struct BindNamespaceCommand {
    /// Human-readable namespace label (DNS-safe).
    pub label: NamespaceLabel,

    /// SHA-256 hex digest of the bound working directory path.
    pub cwd_hash: Option<String>,

    /// Initial DEK version for this namespace (must be >= 1).
    pub dek_version: u32,
}

/// Output of `BindNamespaceCommand`.
#[derive(Debug)]
pub struct BindNamespaceOutput {
    /// The namespace identifier assigned to this binding.
    pub namespace_id: NamespaceId,

    /// The canonical label for the newly created namespace.
    pub label: NamespaceLabel,
}

impl BindNamespaceCommand {
    /// Execute bind-namespace.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::InvalidInput`] — DEK version is 0.
    /// - [`AppError::Storage`] — persistence failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<BindNamespaceOutput, AppError> {
        ctx.require_unsealed().await?;

        if self.dek_version == 0 {
            return Err(AppError::InvalidInput("dek_version must be >= 1".into()));
        }

        info!(label = %self.label, "bind_namespace: creating namespace");

        let mut ns = NsDomain::new(self.label.clone(), self.dek_version);
        ns.cwd_hash = self.cwd_hash.clone();

        let ns_id = ns.id;

        ctx.storage.put_namespace(&ns).await?;

        // Audit.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Bind,
            AuditOutcome::Allow,
            ns_id,
        )
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!(namespace_id = %ns_id, label = %self.label, "bind_namespace: namespace bound");
        Ok(BindNamespaceOutput {
            namespace_id: ns_id,
            label: self.label.clone(),
        })
    }
}
