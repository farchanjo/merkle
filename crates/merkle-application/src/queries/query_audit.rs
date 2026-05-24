//! `QueryAuditQuery` — read audit log entries matching a filter.

use merkle_domain_audit_compliance::{
    AppendParams, AuditEntry, AuditLog, AuditQuery, AuditWriter, ChainOutcome, ChainVerifier,
};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for audit log queries.
#[derive(Debug, Default)]
pub struct QueryAuditQuery {
    /// Filter to apply against the stored audit log.
    pub filter: AuditQuery,
    /// When `true`, run the BLAKE3 chain verifier on the returned entries and
    /// populate [`QueryAuditOutput::chain_valid`] with the result (ADR-0009
    /// §Validation).
    pub verify_chain: bool,
}

/// Output of `QueryAuditQuery`.
#[derive(Debug)]
pub struct QueryAuditOutput {
    /// Matching audit entries in ascending sequence order.
    pub entries: Vec<AuditEntry>,
    /// `Some(true)` when the chain is intact, `Some(false)` when a violation
    /// was detected, or `None` when `verify_chain` was not requested.
    pub chain_valid: Option<bool>,
}

impl QueryAuditQuery {
    /// Execute query-audit.
    ///
    /// When `self.verify_chain` is `true`, the query additionally:
    ///
    /// 1. Rebuilds an in-memory [`AuditLog`] by re-appending every returned
    ///    entry (matching the pattern from [`crate::queries::verify_chain`]).
    /// 2. Loads the persisted [`PinnedHead`] so truncation detection can run.
    /// 3. Calls [`ChainVerifier::verify_full`] and maps the outcome to a
    ///    `bool`.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::Storage`] — storage query failed.
    /// - [`AppError::Domain`] — chain rebuild or pinned-head lookup failed
    ///   (only possible when `verify_chain == true`).
    pub async fn execute(&self, ctx: &AppContext) -> Result<QueryAuditOutput, AppError> {
        ctx.require_unsealed().await?;

        info!("query_audit: querying audit log");

        let entries = ctx.storage.read_audit(&self.filter).await?;

        info!(count = entries.len(), "query_audit: returning entries");

        let chain_valid = if self.verify_chain {
            let hmac_key = ctx.require_hmac_key().await?;

            // Rebuild the in-memory AuditLog by re-appending each entry,
            // following the same pattern used by VerifyChainQuery (doctor).
            let mut log = AuditLog::new();
            for entry in &entries {
                let params = AppendParams::new(entry.op, entry.outcome, entry.namespace_id)
                    .caller_program("merkle-agent");
                AuditWriter::append(&mut log, params, &hmac_key)
                    .map_err(|e| AppError::Domain(format!("chain rebuild failed: {e}")))?;
            }

            let pinned_head = ctx.storage.pinned_head().await?.ok_or_else(|| {
                AppError::Domain("no pinned head found — vault may be uninitialized".into())
            })?;

            let result = ChainVerifier::verify_full(&log, &pinned_head, &hmac_key);
            let intact = matches!(result.outcome, ChainOutcome::Intact);
            info!(
                outcome = ?result.outcome,
                entries_checked = result.entries_checked,
                "query_audit: chain verification complete"
            );
            Some(intact)
        } else {
            None
        };

        Ok(QueryAuditOutput {
            entries,
            chain_valid,
        })
    }
}
