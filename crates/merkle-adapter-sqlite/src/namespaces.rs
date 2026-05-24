//! `put_namespace` / `get_namespace_by_label` / `get_namespace_by_id` SQL operations.

use merkle_domain_secret_storage::Namespace;
use merkle_ports::StorageError;
use merkle_types::{NamespaceId, NamespaceLabel};
use sqlx::SqlitePool;

use crate::error::AdapterError;
use crate::mappers::{id_to_blob, row_to_namespace, uuid_to_blob};

/// Upsert a [`Namespace`] row (INSERT OR REPLACE).
pub(crate) async fn put_namespace(pool: &SqlitePool, ns: &Namespace) -> Result<(), StorageError> {
    let id_blob = id_to_blob!(ns.id);
    let policy_id_blob: Option<Vec<u8>> = ns.policy_id.map(uuid_to_blob);
    let label = ns.label.as_str().to_owned();
    let dek_version = i64::from(ns.dek_version);
    let created_at = ns.created_at.to_string();

    sqlx::query(
        r"INSERT INTO namespaces (id, label, cwd_hash, policy_id, dek_version, created_at)
          VALUES (?1, ?2, ?3, ?4, ?5, ?6)
          ON CONFLICT(id) DO UPDATE SET
              label       = excluded.label,
              cwd_hash    = excluded.cwd_hash,
              policy_id   = excluded.policy_id,
              dek_version = excluded.dek_version",
    )
    .bind(&id_blob)
    .bind(&label)
    .bind(&ns.cwd_hash)
    .bind(&policy_id_blob)
    .bind(dek_version)
    .bind(&created_at)
    .execute(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    Ok(())
}

/// List all [`Namespace`] rows, ordered by `created_at` ascending.
pub(crate) async fn list_namespaces(pool: &SqlitePool) -> Result<Vec<Namespace>, StorageError> {
    let rows = sqlx::query(
        "SELECT id, label, cwd_hash, policy_id, dek_version, created_at
         FROM namespaces
         ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    rows.iter()
        .map(|r| row_to_namespace(r).map_err(StorageError::from))
        .collect()
}

/// Fetch a [`Namespace`] by its label, returning `None` if absent.
pub(crate) async fn get_namespace_by_label(
    pool: &SqlitePool,
    label: &NamespaceLabel,
) -> Result<Option<Namespace>, StorageError> {
    let label_str = label.as_str().to_owned();

    let row = sqlx::query(
        "SELECT id, label, cwd_hash, policy_id, dek_version, created_at
         FROM namespaces WHERE label = ?1",
    )
    .bind(label_str)
    .fetch_optional(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    row.map(|r| row_to_namespace(&r).map_err(StorageError::from))
        .transpose()
}

/// Fetch a [`Namespace`] by its opaque ID (BLOB primary key), returning `None` if absent.
///
/// Added for Bug #1 (ADR-0025): lets the companion-socket handler resolve the
/// human-readable label from the `namespace_id` path parameter so the handle
/// URI first segment is the bound label, not the secret name.
pub(crate) async fn get_namespace_by_id(
    pool: &SqlitePool,
    id: &NamespaceId,
) -> Result<Option<Namespace>, StorageError> {
    let id_blob = id_to_blob!(*id);

    let row = sqlx::query(
        "SELECT id, label, cwd_hash, policy_id, dek_version, created_at
         FROM namespaces WHERE id = ?1",
    )
    .bind(id_blob)
    .fetch_optional(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    row.map(|r| row_to_namespace(&r).map_err(StorageError::from))
        .transpose()
}
