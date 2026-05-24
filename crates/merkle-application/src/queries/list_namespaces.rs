//! `ListNamespacesQuery` — list all namespaces visible in this vault.
//!
//! The Storage port does not yet expose a `list_namespaces` method (Phase 1
//! scope). This query returns a single namespace looked up by label as a
//! convenience until a bulk list is added to the port trait.

use merkle_domain_secret_storage::Namespace;
use merkle_types::NamespaceLabel;
use tracing::info;

use crate::{AppContext, AppError};

/// Input for listing namespaces.
#[derive(Debug, Default)]
pub struct ListNamespacesQuery {
    /// Optional label filter. When `Some`, only the namespace with this label
    /// is returned. When `None`, all namespaces are returned (requires a
    /// future `Storage::list_namespaces` extension — currently returns empty).
    pub label: Option<NamespaceLabel>,
}

/// Output of `ListNamespacesQuery`.
#[derive(Debug)]
pub struct ListNamespacesOutput {
    /// Matching namespace records.
    pub namespaces: Vec<Namespace>,
}

impl ListNamespacesQuery {
    /// Execute list-namespaces.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::Storage`] — storage query failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<ListNamespacesOutput, AppError> {
        ctx.require_unsealed().await?;

        info!("list_namespaces: querying storage");

        let namespaces = if let Some(label) = &self.label {
            let ns = ctx.storage.get_namespace_by_label(label).await?;
            ns.into_iter().collect()
        } else {
            // Full namespace listing requires a future port extension;
            // return empty until the port trait is extended.
            Vec::new()
        };

        info!(count = namespaces.len(), "list_namespaces: returning");
        Ok(ListNamespacesOutput { namespaces })
    }
}
