//! `SearchSecretsCommand` — weighted BM25 ranked full-text search (ADR-0027).
//!
//! Delegates to [`Storage::search_secrets`] which executes the ranked FTS5
//! query template from ADR-0027 §Index Schema. Returns `RankedSecret` items
//! ordered by BM25 score (most-negative = best match), with per-field
//! highlight snippets and pagination metadata (`total`, `has_more`).
//!
//! The operation is audited with `op=search`.

use merkle_ports::{RankedSearchParams, RankedSearchResult};
use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for searching secrets via weighted BM25 FTS5 (ADR-0027).
#[derive(Debug)]
pub struct SearchSecretsCommand {
    /// Namespace to search within.
    pub namespace_id: NamespaceId,
    /// FTS5 MATCH expression (non-empty).
    pub query: String,
    /// Maximum results per page (default 10, max 50).
    pub limit: u32,
    /// Zero-based offset for pagination of ranked results.
    pub offset: u32,
}

/// Output of `SearchSecretsCommand` — ranked results with pagination metadata.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SearchSecretsOutput {
    /// Ranked results (public metadata + score + highlights; no private blob).
    pub result: RankedSearchResult,
}

impl SearchSecretsCommand {
    /// Execute ranked search.
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

        info!(
            namespace = %self.namespace_id,
            query = %self.query,
            limit = self.limit,
            offset = self.offset,
            "search_secrets: executing weighted BM25 FTS5 query"
        );

        let params = RankedSearchParams {
            fts_query: self.query.clone(),
            limit: self.limit,
            offset: self.offset,
        };

        let result = ctx
            .storage
            .search_secrets(&self.namespace_id, params)
            .await?;

        // Audit: op=search.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let audit_params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Search,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, audit_params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        drop(log);
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!(
            count = result.items.len(),
            total = result.total,
            has_more = result.has_more,
            "search_secrets: returning ranked results"
        );
        Ok(SearchSecretsOutput { result })
    }
}
