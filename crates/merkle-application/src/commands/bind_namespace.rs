//! `BindNamespaceCommand` — get-or-create a namespace and bind it to a session.
//!
//! Per ADR-0026 the command is idempotent: when the label already exists in
//! storage the existing namespace is resolved and returned without a new INSERT
//! or audit entry. Only the first bind for a given label writes to storage.

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
    /// Execute bind-namespace (idempotent get-or-create, ADR-0026).
    ///
    /// Returns the existing namespace when the label is already present in
    /// storage — no INSERT, no audit entry. Appends an audit entry only on
    /// first creation.
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

        // Resolve existing namespace; skip INSERT + audit on re-bind.
        if let Some(existing) = ctx.storage.get_namespace_by_label(&self.label).await? {
            info!(
                namespace_id = %existing.id,
                label = %self.label,
                "bind_namespace: resolved existing namespace (idempotent)"
            );
            return Ok(BindNamespaceOutput {
                namespace_id: existing.id,
                label: existing.label,
            });
        }

        // First bind for this label: create, persist, and audit.
        let mut ns = NsDomain::new(self.label.clone(), self.dek_version);
        ns.cwd_hash = self.cwd_hash.clone();
        let ns_id = ns.id;

        ctx.storage.put_namespace(&ns).await?;

        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Bind,
            AuditOutcome::Allow,
            ns_id,
        )
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(namespace_id = %ns_id, label = %self.label, "bind_namespace: namespace created and bound");
        Ok(BindNamespaceOutput {
            namespace_id: ns_id,
            label: self.label.clone(),
        })
    }
}
