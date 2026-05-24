//! `SearchSecretsCommand` — full-text search over public metadata via FTS5.
//!
//! Delegates to [`Storage::list_secrets`] with `fts_query` populated. Returns
//! matching secrets (public metadata only — private blobs present in the
//! struct but the driving adapter is responsible for omitting them). The
//! operation is audited with `op=search`.

use merkle_domain_secret_storage::Secret;
use merkle_ports::SecretFilter;
use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for searching secrets.
#[derive(Debug)]
pub struct SearchSecretsCommand {
    /// Namespace to search within.
    pub namespace_id: NamespaceId,
    /// FTS5 query string.
    pub query: String,
    /// Maximum number of results to return; `None` means no limit.
    pub limit: Option<u32>,
}

/// Output of `SearchSecretsCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SearchSecretsOutput {
    /// Matching secrets.
    pub secrets: Vec<Secret>,
}

impl SearchSecretsCommand {
    /// Execute search-secrets.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::InvalidInput`] — empty query string.
    /// - [`AppError::Storage`] — storage query or audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<SearchSecretsOutput, AppError> {
        ctx.require_unsealed().await?;

        if self.query.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "search query must not be empty".into(),
            ));
        }

        info!(namespace = %self.namespace_id, query = %self.query, "search_secrets: executing FTS5 query");

        let filter = SecretFilter {
            fts_query: Some(self.query.clone()),
            limit: self.limit,
            tag_match: None,
            name_pattern: None,
            expires_before: None,
        };

        let secrets = ctx.storage.list_secrets(&self.namespace_id, filter).await?;

        // Audit: op=search.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Search,
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

        info!(count = secrets.len(), "search_secrets: returning results");
        Ok(SearchSecretsOutput { secrets })
    }
}
