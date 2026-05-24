//! [`Storage`] driven port — persistence abstraction for all bounded contexts.
//!
//! Adapters implement [`Storage`] against a concrete backend (e.g. SQLite).
//! Domain crates call through this trait; they never import adapter crates.

use async_trait::async_trait;
use merkle_domain_access_mediation as am;
use merkle_domain_audit_compliance as ac;
use merkle_domain_backup_recovery as br;
use merkle_domain_policy_permissions as pp;
use merkle_domain_secret_storage as ss;
use merkle_types::{Handle, NamespaceId, NamespaceLabel, SecretId};
use serde::{Deserialize, Serialize};

use crate::error::StorageError;

/// Filter parameters for [`Storage::list_secrets`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretFilter {
    /// Require all listed tags to be present on each returned secret.
    pub tag_match: Option<Vec<merkle_types::Tag>>,
    /// Substring or glob pattern matched against the secret name.
    pub name_pattern: Option<String>,
    /// Return only secrets whose expiry timestamp is before this value.
    pub expires_before: Option<merkle_types::Rfc3339Timestamp>,
    /// Full-text search query evaluated against public metadata fields.
    pub fts_query: Option<String>,
    /// Maximum number of results to return; `None` means no limit.
    pub limit: Option<u32>,
}

/// Driven port for all persistent storage operations.
///
/// A single [`Storage`] implementation covers all bounded-context writes so
/// that atomic cross-aggregate transactions can be expressed as a single
/// backend round-trip when needed.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Upsert a [`Secret`](ss::Secret) aggregate into storage.
    async fn put_secret(&self, secret: &ss::Secret) -> Result<(), StorageError>;

    /// Retrieve a [`Secret`](ss::Secret) by its opaque handle, or `None` if absent.
    async fn get_secret_by_handle(
        &self,
        handle: &Handle,
    ) -> Result<Option<ss::Secret>, StorageError>;

    /// List secrets in a namespace, applying the supplied filter.
    async fn list_secrets(
        &self,
        namespace_id: &NamespaceId,
        filter: SecretFilter,
    ) -> Result<Vec<ss::Secret>, StorageError>;

    /// Hard-delete a secret by its [`SecretId`].
    async fn delete_secret(&self, secret_id: &SecretId) -> Result<(), StorageError>;

    /// Upsert a [`Namespace`](ss::Namespace) entity.
    async fn put_namespace(&self, ns: &ss::Namespace) -> Result<(), StorageError>;

    /// Fetch a [`Namespace`](ss::Namespace) by its human-readable label, or `None`.
    async fn get_namespace_by_label(
        &self,
        label: &NamespaceLabel,
    ) -> Result<Option<ss::Namespace>, StorageError>;

    /// List all persisted namespaces in the vault.
    ///
    /// Returns rows ordered by `created_at` ascending (storage-defined).
    /// Pagination is NOT applied at this layer; callers truncate as needed.
    /// Required by ADR-0025 §Bug #2.
    async fn list_namespaces(&self) -> Result<Vec<ss::Namespace>, StorageError>;

    /// Fetch a [`Namespace`](ss::Namespace) by its opaque [`NamespaceId`], or `None`.
    ///
    /// Added for Bug #1 (ADR-0025): the companion-socket `put_secret` handler
    /// must resolve the human-readable label from the `namespace_id` received
    /// in the request path so that the handle URI first segment equals the bound
    /// label (e.g. `vault://mcp-smoke/…`), not the secret name.
    async fn get_namespace_by_id(
        &self,
        id: &NamespaceId,
    ) -> Result<Option<ss::Namespace>, StorageError>;

    /// Append an immutable [`AuditEntry`](ac::AuditEntry) to the audit log.
    async fn append_audit_entry(&self, entry: &ac::AuditEntry) -> Result<(), StorageError>;

    /// Query the audit log according to the supplied [`AuditQuery`](ac::AuditQuery).
    async fn read_audit(&self, query: &ac::AuditQuery)
    -> Result<Vec<ac::AuditEntry>, StorageError>;

    /// Read the current [`PinnedHead`](ac::PinnedHead) record, or `None` on first boot.
    async fn pinned_head(&self) -> Result<Option<ac::PinnedHead>, StorageError>;

    /// Atomically replace the [`PinnedHead`](ac::PinnedHead) record.
    async fn update_pinned_head(&self, head: &ac::PinnedHead) -> Result<(), StorageError>;

    /// Persist a completed [`Backup`](br::backup::Backup) aggregate.
    async fn put_backup(&self, backup: &br::backup::Backup) -> Result<(), StorageError>;

    /// List all backups associated with a namespace.
    async fn list_backups(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<Vec<br::backup::Backup>, StorageError>;

    /// Upsert a [`NamespacePolicy`](pp::NamespacePolicy) aggregate.
    async fn put_namespace_policy(&self, policy: &pp::NamespacePolicy) -> Result<(), StorageError>;

    /// Retrieve the active [`NamespacePolicy`](pp::NamespacePolicy) for a namespace, or `None`.
    async fn get_namespace_policy(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<Option<pp::NamespacePolicy>, StorageError>;

    /// Upsert a [`CompanionDevice`](am::companion_device::CompanionDevice) enrollment record.
    async fn put_companion_device(
        &self,
        device: &am::companion_device::CompanionDevice,
    ) -> Result<(), StorageError>;

    /// Return all enrolled companion devices.
    async fn list_companion_devices(
        &self,
    ) -> Result<Vec<am::companion_device::CompanionDevice>, StorageError>;
}
