//! `ListNamespacesQuery` — list all namespaces visible in this vault.
//!
//! ADR-0025 §Bug #2 (2026-05-24): `Storage::list_namespaces` port extension
//! landed; the `label: None` branch now performs a full bulk list instead of
//! returning empty.

use merkle_domain_secret_storage::Namespace;
use merkle_types::NamespaceLabel;
use tracing::info;

use crate::{AppContext, AppError};

/// Input for listing namespaces.
#[derive(Debug, Default)]
pub struct ListNamespacesQuery {
    /// Optional label filter. When `Some`, only the namespace with this label
    /// is returned. When `None`, all namespaces are returned via
    /// `Storage::list_namespaces` (ADR-0025 §Bug #2).
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
            // ADR-0025 §Bug #2 — port extension landed 2026-05-24.
            ctx.storage.list_namespaces().await?
        };

        info!(count = namespaces.len(), "list_namespaces: returning");
        Ok(ListNamespacesOutput { namespaces })
    }
}
