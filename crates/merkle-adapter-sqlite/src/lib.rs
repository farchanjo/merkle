//! # merkle-adapter-sqlite
//!
//! Driven-port adapter: implements [`merkle_ports::Storage`] using `sqlx` +
//! SQLite with WAL mode, FTS5 full-text search (ADR-0013), append-only audit
//! triggers (ADR-0009), and per-blob XChaCha20-Poly1305 AEAD storage routing
//! (ADR-0003).
//!
//! ## Usage
//!
//! ```ignore
//! use merkle_adapter_sqlite::SqliteStorage;
//!
//! let storage = SqliteStorage::open("sqlite:merkle.db").await.unwrap();
//! // storage implements merkle_ports::Storage
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

mod audit;
mod backups;
mod devices;
mod error;
mod mappers;
mod namespaces;
mod policies;
pub mod schema;
mod secrets;

use async_trait::async_trait;
use merkle_domain_access_mediation::companion_device::CompanionDevice;
use merkle_domain_audit_compliance::{AuditBaseline, AuditEntry, AuditQuery, PinnedHead};
use merkle_domain_backup_recovery::backup::Backup;
use merkle_domain_policy_permissions::NamespacePolicy;
use merkle_domain_secret_storage::{Namespace, Secret};
use merkle_ports::{RankedSearchParams, RankedSearchResult, SecretFilter, Storage, StorageError};
use merkle_types::{Handle, NamespaceId, NamespaceLabel, SecretId};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::str::FromStr;
use tracing::instrument;

/// SQLite-backed implementation of [`merkle_ports::Storage`].
///
/// Wraps a `sqlx::SqlitePool`. WAL mode and foreign keys are configured on
/// every new connection via `SqliteConnectOptions`.
///
/// Construct via [`SqliteStorage::open`]; drop when finished.
#[derive(Debug, Clone)]
pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    /// Open (or create) a SQLite database at `database_url`, run all pending
    /// migrations, and return a ready-to-use `SqliteStorage`.
    ///
    /// The `database_url` follows the `sqlx` format:
    /// - `sqlite:path/to/file.db` — file-based
    /// - `sqlite::memory:` — in-process in-memory (useful for tests)
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if the database cannot be opened or migrations
    /// fail.
    pub async fn open(database_url: &str) -> Result<Self, StorageError> {
        let opts = SqliteConnectOptions::from_str(database_url)
            .map_err(|e| StorageError::Backend(Box::new(e)))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            // Overwrite freed pages with zeros so deleted/rotated secret
            // ciphertext does not linger in the file's free list.
            .pragma("secure_delete", "ON")
            // Block (up to 5s) instead of returning SQLITE_BUSY immediately when
            // a concurrent writer holds the lock — the pool has 5 connections
            // and WAL still serialises writers.
            .busy_timeout(std::time::Duration::from_secs(5));

        // For in-memory SQLite (`:memory:`), each connection is an independent
        // database. Use max_connections(1) to ensure all operations share the
        // same DB instance and the schema created by migrations is visible to
        // subsequent queries.
        let pool_max = if database_url.contains(":memory:") {
            1
        } else {
            5
        };
        let pool = SqlitePoolOptions::new()
            .max_connections(pool_max)
            .connect_with(opts)
            .await
            .map_err(|e| StorageError::Backend(Box::new(e)))?;

        let storage = Self { pool };
        storage.run_migrations().await?;
        Ok(storage)
    }

    /// Run all pending embedded SQL migrations.
    ///
    /// Idempotent — safe to call on an already-migrated database.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if any migration fails.
    pub async fn run_migrations(&self) -> Result<(), StorageError> {
        sqlx::migrate!("src/migrations")
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::Backend(Box::new(e)))?;
        Ok(())
    }

    /// Drain the connection pool and close the database.
    pub async fn close(self) {
        self.pool.close().await;
    }
}

#[async_trait]
impl Storage for SqliteStorage {
    #[instrument(skip(self, secret), fields(handle = %secret.handle))]
    async fn put_secret(&self, secret: &Secret) -> Result<(), StorageError> {
        secrets::put_secret(&self.pool, secret).await
    }

    #[instrument(skip(self), fields(handle = %handle))]
    async fn get_secret_by_handle(&self, handle: &Handle) -> Result<Option<Secret>, StorageError> {
        secrets::get_secret_by_handle(&self.pool, handle).await
    }

    #[instrument(skip(self, filter))]
    async fn list_secrets(
        &self,
        namespace_id: &NamespaceId,
        filter: SecretFilter,
    ) -> Result<Vec<Secret>, StorageError> {
        secrets::list_secrets(&self.pool, namespace_id, filter).await
    }

    #[instrument(skip(self))]
    async fn delete_secret(&self, secret_id: &SecretId) -> Result<(), StorageError> {
        secrets::delete_secret(&self.pool, secret_id).await
    }

    #[instrument(skip(self, params), fields(fts_query = %params.fts_query, limit = params.limit, offset = params.offset))]
    async fn search_secrets(
        &self,
        namespace_id: &NamespaceId,
        params: RankedSearchParams,
    ) -> Result<RankedSearchResult, StorageError> {
        secrets::search_secrets(&self.pool, namespace_id, params).await
    }

    #[instrument(skip(self))]
    async fn check_fts5_consistency(&self) -> Result<(), StorageError> {
        secrets::check_fts5_consistency(&self.pool).await
    }

    #[instrument(skip(self, ns), fields(label = %ns.label))]
    async fn put_namespace(&self, ns: &Namespace) -> Result<(), StorageError> {
        namespaces::put_namespace(&self.pool, ns).await
    }

    #[instrument(skip(self), fields(label = %label))]
    async fn get_namespace_by_label(
        &self,
        label: &NamespaceLabel,
    ) -> Result<Option<Namespace>, StorageError> {
        namespaces::get_namespace_by_label(&self.pool, label).await
    }

    #[instrument(skip(self))]
    async fn list_namespaces(&self) -> Result<Vec<Namespace>, StorageError> {
        namespaces::list_namespaces(&self.pool).await
    }

    #[instrument(skip(self), fields(id = %id))]
    async fn get_namespace_by_id(
        &self,
        id: &NamespaceId,
    ) -> Result<Option<Namespace>, StorageError> {
        namespaces::get_namespace_by_id(&self.pool, id).await
    }

    #[instrument(skip(self, entry), fields(seq = entry.seq))]
    async fn append_audit_entry(&self, entry: &AuditEntry) -> Result<(), StorageError> {
        audit::append_audit_entry(&self.pool, entry).await
    }

    #[instrument(skip(self, query))]
    async fn read_audit(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>, StorageError> {
        audit::read_audit(&self.pool, query).await
    }

    #[instrument(skip(self))]
    async fn pinned_head(&self) -> Result<Option<PinnedHead>, StorageError> {
        audit::pinned_head(&self.pool).await
    }

    #[instrument(skip(self, head), fields(seq = head.head_seq))]
    async fn update_pinned_head(&self, head: &PinnedHead) -> Result<(), StorageError> {
        audit::update_pinned_head(&self.pool, head).await
    }

    async fn audit_baseline(&self) -> Result<Option<AuditBaseline>, StorageError> {
        audit::audit_baseline(&self.pool).await
    }

    async fn set_audit_baseline(&self, baseline: &AuditBaseline) -> Result<(), StorageError> {
        audit::set_audit_baseline(&self.pool, baseline).await
    }

    #[instrument(skip(self, backup), fields(id = %backup.id))]
    async fn put_backup(&self, backup: &Backup) -> Result<(), StorageError> {
        backups::put_backup(&self.pool, backup).await
    }

    #[instrument(skip(self))]
    async fn list_backups(&self, namespace_id: &NamespaceId) -> Result<Vec<Backup>, StorageError> {
        backups::list_backups(&self.pool, namespace_id).await
    }

    #[instrument(skip(self, policy))]
    async fn put_namespace_policy(&self, policy: &NamespacePolicy) -> Result<(), StorageError> {
        policies::put_namespace_policy(&self.pool, policy).await
    }

    #[instrument(skip(self))]
    async fn get_namespace_policy(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<Option<NamespacePolicy>, StorageError> {
        policies::get_namespace_policy(&self.pool, namespace_id).await
    }

    #[instrument(skip(self, device), fields(device_id = %device.device_id))]
    async fn put_companion_device(&self, device: &CompanionDevice) -> Result<(), StorageError> {
        devices::put_companion_device(&self.pool, device).await
    }

    #[instrument(skip(self))]
    async fn list_companion_devices(&self) -> Result<Vec<CompanionDevice>, StorageError> {
        devices::list_companion_devices(&self.pool).await
    }
}
