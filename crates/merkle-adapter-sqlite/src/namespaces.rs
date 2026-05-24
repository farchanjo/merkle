//! `put_namespace` / `get_namespace_by_label` SQL operations.

use merkle_domain_secret_storage::Namespace;
use merkle_ports::StorageError;
use merkle_types::NamespaceLabel;
use sqlx::SqlitePool;

use crate::error::AdapterError;
use crate::mappers::{id_to_blob, row_to_namespace, uuid_to_blob};

/// Upsert a [`Namespace`] row (INSERT OR REPLACE).
pub(crate) async fn put_namespace(
    pool: &SqlitePool,
    ns: &Namespace,
) -> Result<(), StorageError> {
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
