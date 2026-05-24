//! `QueryAuditQuery` — read audit log entries matching a filter.

use merkle_domain_audit_compliance::{AuditEntry, AuditQuery};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for audit log queries.
#[derive(Debug, Default)]
pub struct QueryAuditQuery {
    /// Filter to apply against the stored audit log.
    pub filter: AuditQuery,
}

/// Output of `QueryAuditQuery`.
#[derive(Debug)]
pub struct QueryAuditOutput {
    /// Matching audit entries in ascending sequence order.
    pub entries: Vec<AuditEntry>,
}

impl QueryAuditQuery {
    /// Execute query-audit.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::Storage`] — storage query failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<QueryAuditOutput, AppError> {
        ctx.require_unsealed().await?;

        info!("query_audit: querying audit log");

        let entries = ctx.storage.read_audit(&self.filter).await?;

        info!(count = entries.len(), "query_audit: returning entries");
        Ok(QueryAuditOutput { entries })
    }
}
