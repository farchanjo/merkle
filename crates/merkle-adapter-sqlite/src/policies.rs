//! `put_namespace_policy` / `get_namespace_policy` SQL operations.

use merkle_domain_policy_permissions::NamespacePolicy;
use merkle_ports::StorageError;
use merkle_types::NamespaceId;
use sqlx::SqlitePool;

use crate::error::AdapterError;
use crate::mappers::{row_to_namespace_policy, uuid_to_blob};

/// Upsert a [`NamespacePolicy`].
pub(crate) async fn put_namespace_policy(
    pool: &SqlitePool,
    policy: &NamespacePolicy,
) -> Result<(), StorageError> {
    let id_blob = uuid_to_blob(policy.id);
    let ns_blob = uuid_to_blob(policy.namespace_id.inner());
    let policy_json = serde_json::to_string(policy)
        .map_err(AdapterError::Json)
        .map_err(StorageError::from)?;
    let created_at = policy.created_at.to_string();

    sqlx::query(
        r"INSERT INTO namespace_policies (id, namespace_id, policy_json, created_at)
          VALUES (?1, ?2, ?3, ?4)
          ON CONFLICT(namespace_id) DO UPDATE SET
              id          = excluded.id,
              policy_json = excluded.policy_json,
              created_at  = excluded.created_at",
    )
    .bind(&id_blob)
    .bind(&ns_blob)
    .bind(&policy_json)
    .bind(&created_at)
    .execute(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    Ok(())
}

/// Fetch the [`NamespacePolicy`] for a namespace, returning `None` when absent.
pub(crate) async fn get_namespace_policy(
    pool: &SqlitePool,
    namespace_id: &NamespaceId,
) -> Result<Option<NamespacePolicy>, StorageError> {
    let ns_blob = uuid_to_blob(namespace_id.inner());

    let row = sqlx::query(
        "SELECT policy_json FROM namespace_policies WHERE namespace_id = ?1",
    )
    .bind(ns_blob)
    .fetch_optional(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    row.map(|r| row_to_namespace_policy(&r).map_err(StorageError::from))
        .transpose()
}
