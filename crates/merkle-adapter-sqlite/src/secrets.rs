//! `put_secret` / `get_secret_by_handle` / `list_secrets` / `delete_secret`.

use merkle_domain_secret_storage::{Secret, secret_version::SecretVersion};
use merkle_ports::{SecretFilter, StorageError};
use merkle_types::{Handle, NamespaceId, SecretId};
use sqlx::{Row, SqlitePool};

use crate::error::AdapterError;
use crate::mappers::{id_to_blob, row_to_secret, row_to_secret_version, uuid_to_blob};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Upsert a single `SecretVersion` row, using `parent_id` as the canonical
/// `secret_id` (overrides `v.secret_id` which may carry a placeholder value
/// set before `Secret::new` generated the real identity).
async fn upsert_version_with_parent(
    pool: &SqlitePool,
    v: &SecretVersion,
    parent_id: &SecretId,
) -> Result<(), AdapterError> {
    let id_blob = uuid_to_blob(v.id.inner());
    let secret_id_blob = id_to_blob!(parent_id);
    let version_no = i64::from(v.version_no);
    let dek_version = i64::from(v.dek_version);
    let created_at = v.created_at.to_string();
    let deprecated_at = v.deprecated_at.as_ref().map(ToString::to_string);

    sqlx::query(
        r"INSERT INTO secret_versions
            (id, secret_id, version_no, ciphertext, nonce, aead_tag,
             associated_data, dek_version, created_at, deprecated_at)
          VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
          ON CONFLICT(id) DO UPDATE SET
              deprecated_at = excluded.deprecated_at",
    )
    .bind(&id_blob)
    .bind(&secret_id_blob)
    .bind(version_no)
    .bind(&v.blob.ciphertext)
    .bind(v.blob.nonce.as_slice())
    .bind(v.blob.aead_tag.as_slice())
    .bind(&v.blob.associated_data)
    .bind(dek_version)
    .bind(&created_at)
    .bind(&deprecated_at)
    .execute(pool)
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

/// Upsert a [`Secret`] and all its [`SecretVersion`]s atomically.
pub(crate) async fn put_secret(pool: &SqlitePool, secret: &Secret) -> Result<(), StorageError> {
    let id_blob = id_to_blob!(secret.id);
    let ns_blob = id_to_blob!(secret.namespace_id);
    let handle_str = secret.handle.to_string();
    let category_str = secret.category.to_string();
    let sensitivity_str = secret.sensitivity.to_string();
    let public_metadata_json = serde_json::to_string(&secret.public_metadata)
        .map_err(AdapterError::Json)
        .map_err(StorageError::from)?;
    let tags_json = serde_json::to_string(&secret.tags)
        .map_err(AdapterError::Json)
        .map_err(StorageError::from)?;
    let current_version_id_blob = uuid_to_blob(secret.current_version_id().inner());
    let created_at = secret.created_at.to_string();

    let mut tx = pool
        .begin()
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    sqlx::query(
        r"INSERT INTO secrets
            (id, namespace_id, handle, category, sensitivity,
             public_metadata_json, tags_json, current_version_id, created_at)
          VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
          ON CONFLICT(id) DO UPDATE SET
              handle               = excluded.handle,
              sensitivity          = excluded.sensitivity,
              public_metadata_json = excluded.public_metadata_json,
              tags_json            = excluded.tags_json,
              current_version_id   = excluded.current_version_id",
    )
    .bind(&id_blob)
    .bind(&ns_blob)
    .bind(&handle_str)
    .bind(&category_str)
    .bind(&sensitivity_str)
    .bind(&public_metadata_json)
    .bind(&tags_json)
    .bind(&current_version_id_blob)
    .bind(&created_at)
    .execute(&mut *tx)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    tx.commit()
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    // Versions use the pool directly (each version upsert is its own mini-tx).
    // We override `secret_id` in the write path to guarantee it always matches
    // the parent `Secret::id` — the domain type doesn't enforce this at
    // construction time, so a newly-created Secret may carry a placeholder id
    // in the initial version's `secret_id` field.
    for version in secret.versions() {
        upsert_version_with_parent(pool, version, &secret.id)
            .await
            .map_err(StorageError::from)?;
    }

    Ok(())
}

/// Fetch a [`Secret`] (with all its versions) by its handle URI.
pub(crate) async fn get_secret_by_handle(
    pool: &SqlitePool,
    handle: &Handle,
) -> Result<Option<Secret>, StorageError> {
    let handle_str = handle.to_string();

    let secret_row = sqlx::query(
        "SELECT id, namespace_id, handle, category, sensitivity,
                public_metadata_json, tags_json, current_version_id, created_at
         FROM secrets WHERE handle = ?1",
    )
    .bind(&handle_str)
    .fetch_optional(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    let Some(row) = secret_row else {
        return Ok(None);
    };

    let id_bytes: Vec<u8> = row
        .try_get("id")
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    let versions = load_versions_for_secret(pool, &id_bytes).await?;
    let secret = row_to_secret(&row, &versions).map_err(StorageError::from)?;
    Ok(Some(secret))
}

/// Load all [`SecretVersion`]s belonging to a secret identified by its id blob.
async fn load_versions_for_secret(
    pool: &SqlitePool,
    secret_id_blob: &[u8],
) -> Result<Vec<SecretVersion>, StorageError> {
    let rows = sqlx::query(
        "SELECT id, secret_id, version_no, ciphertext, nonce, aead_tag,
                associated_data, dek_version, created_at, deprecated_at
         FROM secret_versions WHERE secret_id = ?1 ORDER BY version_no ASC",
    )
    .bind(secret_id_blob)
    .fetch_all(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    rows.iter()
        .map(|r| row_to_secret_version(r).map_err(StorageError::from))
        .collect()
}

/// List secrets in a namespace matching the supplied filter.
pub(crate) async fn list_secrets(
    pool: &SqlitePool,
    namespace_id: &NamespaceId,
    filter: SecretFilter,
) -> Result<Vec<Secret>, StorageError> {
    let ns_blob = id_to_blob!(namespace_id);

    // Build WHERE conditions dynamically.
    let mut conditions: Vec<String> = vec!["s.namespace_id = ?1".to_owned()];
    let mut bind_idx: u32 = 2;

    let use_fts = filter.fts_query.is_some();
    if use_fts {
        conditions.push(format!(
            "s.rowid IN (SELECT rowid FROM secrets_fts WHERE secrets_fts MATCH ?{bind_idx})"
        ));
        bind_idx += 1;
    }

    if filter.name_pattern.is_some() {
        conditions.push(format!("s.handle LIKE ?{bind_idx}"));
        bind_idx += 1;
    }

    if filter.expires_before.is_some() {
        conditions.push(format!(
            "json_extract(s.public_metadata_json, '$.expires_at') < ?{bind_idx}"
        ));
        bind_idx += 1;
    }

    let limit_clause = filter
        .limit
        .map(|l| format!(" LIMIT {l}"))
        .unwrap_or_default();

    let _ = bind_idx; // consumed above

    let where_clause = conditions.join(" AND ");
    let sql = format!(
        "SELECT s.id, s.namespace_id, s.handle, s.category, s.sensitivity,
                s.public_metadata_json, s.tags_json, s.current_version_id, s.created_at
         FROM secrets s WHERE {where_clause} ORDER BY s.created_at ASC{limit_clause}"
    );

    let mut q = sqlx::query(&sql).bind(ns_blob);

    if let Some(ref fts) = filter.fts_query {
        q = q.bind(fts.clone());
    }
    if let Some(ref pattern) = filter.name_pattern {
        let like_pattern = pattern.replace('*', "%");
        q = q.bind(like_pattern);
    }
    if let Some(ref exp) = filter.expires_before {
        q = q.bind(exp.to_string());
    }

    let rows = q
        .fetch_all(pool)
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    let mut secrets = Vec::with_capacity(rows.len());
    for row in &rows {
        let id_bytes: Vec<u8> = row
            .try_get("id")
            .map_err(AdapterError::Sqlx)
            .map_err(StorageError::from)?;
        let versions = load_versions_for_secret(pool, &id_bytes).await?;

        // Tag filter applied in Rust (SQL JSON array intersection is verbose in SQLite).
        if let Some(ref required_tags) = filter.tag_match {
            let tags_json: String = row
                .try_get("tags_json")
                .map_err(AdapterError::Sqlx)
                .map_err(StorageError::from)?;
            let tags: Vec<merkle_types::Tag> = serde_json::from_str(&tags_json)
                .map_err(AdapterError::Json)
                .map_err(StorageError::from)?;
            let all_match = required_tags.iter().all(|rt| tags.contains(rt));
            if !all_match {
                continue;
            }
        }

        let secret = row_to_secret(row, &versions).map_err(StorageError::from)?;
        secrets.push(secret);
    }

    Ok(secrets)
}

/// Delete a secret and cascade-delete all its versions (FK ON DELETE CASCADE).
pub(crate) async fn delete_secret(
    pool: &SqlitePool,
    secret_id: &SecretId,
) -> Result<(), StorageError> {
    let id_blob = id_to_blob!(secret_id);

    let result = sqlx::query("DELETE FROM secrets WHERE id = ?1")
        .bind(&id_blob)
        .execute(pool)
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    if result.rows_affected() == 0 {
        return Err(StorageError::NotFound);
    }

    Ok(())
}
