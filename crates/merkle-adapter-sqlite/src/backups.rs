//! `put_backup` / `list_backups` SQL operations.

use merkle_domain_backup_recovery::backup::Backup;
use merkle_ports::StorageError;
use merkle_types::NamespaceId;
use sqlx::{Row, SqlitePool};

use crate::error::AdapterError;
use crate::mappers::{blob_to_namespace_id, blob_to_uuid, uuid_to_blob};

/// Persist a [`Backup`] record.
pub(crate) async fn put_backup(pool: &SqlitePool, backup: &Backup) -> Result<(), StorageError> {
    let id_blob = uuid_to_blob(backup.id);
    let ns_blob = uuid_to_blob(backup.namespace_id.inner());
    let snapshot_id_blob = uuid_to_blob(backup.snapshot_id);
    let trigger_str = serde_json::to_string(&backup.trigger)
        .map_err(AdapterError::Json)
        .map_err(StorageError::from)?;
    let recipients_json = serde_json::to_string(&backup.recipients)
        .map_err(AdapterError::Json)
        .map_err(StorageError::from)?;
    let artifact_json = serde_json::to_string(&backup.artifact)
        .map_err(AdapterError::Json)
        .map_err(StorageError::from)?;
    let hmac_str = backup.hmac.to_string();
    let size_bytes = i64::try_from(backup.size_bytes).unwrap_or(i64::MAX);
    let secret_count = i64::from(backup.secret_count);
    let created_at = backup.created_at.to_string();

    sqlx::query(
        r"INSERT OR REPLACE INTO backups
            (id, namespace_id, snapshot_id, trigger, recipients_json,
             artifact_json, hmac, size_bytes, secret_count, created_at)
          VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
    )
    .bind(&id_blob)
    .bind(&ns_blob)
    .bind(&snapshot_id_blob)
    .bind(&trigger_str)
    .bind(&recipients_json)
    .bind(&artifact_json)
    .bind(&hmac_str)
    .bind(size_bytes)
    .bind(secret_count)
    .bind(&created_at)
    .execute(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    Ok(())
}

/// List all backups for a given namespace, ordered by creation time (newest first).
pub(crate) async fn list_backups(
    pool: &SqlitePool,
    namespace_id: &NamespaceId,
) -> Result<Vec<Backup>, StorageError> {
    let ns_blob = uuid_to_blob(namespace_id.inner());

    let rows = sqlx::query(
        r"SELECT id, namespace_id, snapshot_id, trigger, recipients_json,
                 artifact_json, hmac, size_bytes, secret_count, created_at
          FROM backups WHERE namespace_id = ?1 ORDER BY created_at DESC",
    )
    .bind(ns_blob)
    .fetch_all(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    let mut backups = Vec::with_capacity(rows.len());
    for row in &rows {
        let backup = decode_backup_row(row).map_err(StorageError::from)?;
        backups.push(backup);
    }

    Ok(backups)
}

/// Decode a full `Backup` from individual row columns (reassembles the struct).
fn decode_backup_row(row: &sqlx::sqlite::SqliteRow) -> Result<Backup, AdapterError> {
    use merkle_domain_backup_recovery::{
        artifact::BackupArtifact, recipient::BackupRecipient, trigger::BackupTrigger,
    };
    use merkle_types::{HmacSignature, Rfc3339Timestamp};

    let id_bytes: Vec<u8> = row.try_get("id")?;
    let id = blob_to_uuid(&id_bytes)?;

    let ns_bytes: Vec<u8> = row.try_get("namespace_id")?;
    let namespace_id = blob_to_namespace_id(&ns_bytes)?;

    let snapshot_bytes: Vec<u8> = row.try_get("snapshot_id")?;
    let snapshot_id = blob_to_uuid(&snapshot_bytes)?;

    let trigger_str: String = row.try_get("trigger")?;
    let trigger: BackupTrigger = serde_json::from_str(&trigger_str)?;

    let recipients_json: String = row.try_get("recipients_json")?;
    let recipients: [BackupRecipient; 2] = serde_json::from_str(&recipients_json)?;

    let artifact_json: String = row.try_get("artifact_json")?;
    let artifact: BackupArtifact = serde_json::from_str(&artifact_json)?;

    let hmac_str: String = row.try_get("hmac")?;
    let hmac = hmac_str
        .parse::<HmacSignature>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    let size_bytes_i: i64 = row.try_get("size_bytes")?;
    let secret_count_i: i64 = row.try_get("secret_count")?;

    let created_at_str: String = row.try_get("created_at")?;
    let created_at = created_at_str
        .parse::<Rfc3339Timestamp>()
        .map_err(|e| AdapterError::Parse(e.to_string()))?;

    Ok(Backup {
        id,
        namespace_id,
        snapshot_id,
        trigger,
        recipients,
        artifact,
        hmac,
        size_bytes: u64::try_from(size_bytes_i).unwrap_or(0),
        secret_count: u32::try_from(secret_count_i).unwrap_or(0),
        created_at,
    })
}
