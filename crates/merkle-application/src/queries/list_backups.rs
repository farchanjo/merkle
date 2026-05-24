//! `ListBackupsQuery` — return all backups for a namespace.

use merkle_domain_backup_recovery::backup::Backup;
use merkle_types::NamespaceId;
use std::cmp::Reverse;
use tracing::info;

use crate::{AppContext, AppError};

/// Input for listing backups.
#[derive(Debug)]
pub struct ListBackupsQuery {
    /// Namespace to list backups for.
    pub namespace_id: NamespaceId,
}

/// Output of `ListBackupsQuery`.
#[derive(Debug)]
pub struct ListBackupsOutput {
    /// All backup records for the namespace, newest first.
    pub backups: Vec<Backup>,
}

impl ListBackupsQuery {
    /// Execute list-backups.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::Storage`] — storage query failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<ListBackupsOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(namespace = %self.namespace_id, "list_backups: querying storage");

        let mut backups = ctx.storage.list_backups(&self.namespace_id).await?;
        // Sort newest first.
        backups.sort_by_key(|b| Reverse(b.created_at));

        info!(count = backups.len(), "list_backups: returning");
        Ok(ListBackupsOutput { backups })
    }
}
