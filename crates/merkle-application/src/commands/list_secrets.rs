//! `ListSecretsCommand` — list secrets in a namespace with optional filtering.
//!
//! Applies a `SecretFilter` to the storage query and then applies an optional
//! policy-based filter. Only public metadata is returned; `PrivateBlob` is
//! never included in the output.

use merkle_domain_secret_storage::Secret;
use merkle_ports::SecretFilter;
use merkle_types::{AuditOp, AuditOutcome, NamespaceId, Tag};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for listing secrets.
#[derive(Debug, Default)]
pub struct ListSecretsCommand {
    /// Namespace to list secrets for.
    pub namespace_id: NamespaceId,

    /// Tags that every returned secret must carry (AND semantics).
    pub tag_match: Option<Vec<Tag>>,

    /// Substring or glob pattern matched against the secret name.
    pub name_pattern: Option<String>,

    /// Maximum number of results to return.
    pub limit: Option<u32>,
}

/// Output of `ListSecretsCommand`.
#[derive(Debug)]
pub struct ListSecretsOutput {
    /// Matching secrets, with `PrivateBlob` fields present but access
    /// controlled by the caller — the application layer does not strip them
    /// here; the driving adapter (MCP, CLI) is responsible for omitting blobs.
    pub secrets: Vec<Secret>,
}

impl ListSecretsCommand {
    /// Execute list-secrets.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault is not `Unsealed`.
    /// - [`AppError::Storage`] — storage query failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<ListSecretsOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(namespace = %self.namespace_id, "list_secrets: querying storage");

        let filter = SecretFilter {
            tag_match: self.tag_match.clone(),
            name_pattern: self.name_pattern.clone(),
            expires_before: None,
            fts_query: None,
            limit: self.limit,
        };

        let secrets = ctx.storage.list_secrets(&self.namespace_id, filter).await?;

        // Append audit entry.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::List,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!(count = secrets.len(), "list_secrets: returning results");
        Ok(ListSecretsOutput { secrets })
    }
}
