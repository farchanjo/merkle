//! Durable `restore_plans` SQL operations (Feature 002 / ADR-0034).

use merkle_domain_backup_recovery::restore_plan::RestorePlan;
use merkle_ports::StorageError;
use merkle_types::{Rfc3339Timestamp, UuidV7};
use sqlx::{Row, SqlitePool};

use crate::error::AdapterError;
use crate::mappers::uuid_to_blob;

/// Persist a [`RestorePlan`]. Replaces a non-applied row with the same id.
pub(crate) async fn put_restore_plan(
    pool: &SqlitePool,
    plan: &RestorePlan,
) -> Result<(), StorageError> {
    // Reject overwrite of an already-applied plan.
    if let Some(existing_applied) = restore_plan_applied_at(pool, &plan.id).await? {
        return Err(StorageError::Conflict(format!(
            "restore plan {} already applied at {existing_applied}",
            plan.id
        )));
    }

    let id_blob = uuid_to_blob(plan.id);
    let source_blob = uuid_to_blob(plan.source_backup_id);
    let ns_blob = plan
        .target_namespace
        .map(|ns| uuid_to_blob(ns.inner()))
        .ok_or_else(|| {
            StorageError::Constraint("restore plan requires target_namespace".into())
        })?;
    let mode = serde_json::to_string(&plan.mode)
        .map_err(AdapterError::Json)
        .map_err(StorageError::from)?;
    let plan_json = serde_json::to_string(plan)
        .map_err(AdapterError::Json)
        .map_err(StorageError::from)?;
    let expires_at = plan.expires_at.to_string();
    let validated_at = plan.validated_at.to_string();

    sqlx::query(
        r"INSERT OR REPLACE INTO restore_plans
            (id, source_backup_id, namespace_id, mode, plan_json,
             expires_at, validated_at, applied_at)
          VALUES (?1,?2,?3,?4,?5,?6,?7, NULL)",
    )
    .bind(&id_blob)
    .bind(&source_blob)
    .bind(&ns_blob)
    .bind(&mode)
    .bind(&plan_json)
    .bind(&expires_at)
    .bind(&validated_at)
    .execute(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    Ok(())
}

/// Load a plan by id.
pub(crate) async fn get_restore_plan(
    pool: &SqlitePool,
    plan_id: &UuidV7,
) -> Result<Option<RestorePlan>, StorageError> {
    let id_blob = uuid_to_blob(*plan_id);
    let row = sqlx::query(
        r"SELECT plan_json FROM restore_plans WHERE id = ?1",
    )
    .bind(&id_blob)
    .fetch_optional(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    match row {
        None => Ok(None),
        Some(row) => {
            let plan_json: String = row.try_get("plan_json").map_err(AdapterError::Sqlx)?;
            let plan: RestorePlan = serde_json::from_str(&plan_json)
                .map_err(AdapterError::Json)
                .map_err(StorageError::from)?;
            Ok(Some(plan))
        }
    }
}

/// Return applied_at when the plan has been applied.
pub(crate) async fn restore_plan_applied_at(
    pool: &SqlitePool,
    plan_id: &UuidV7,
) -> Result<Option<Rfc3339Timestamp>, StorageError> {
    let id_blob = uuid_to_blob(*plan_id);
    let row = sqlx::query(r"SELECT applied_at FROM restore_plans WHERE id = ?1")
        .bind(&id_blob)
        .fetch_optional(pool)
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    match row {
        None => Ok(None),
        Some(row) => {
            let applied: Option<String> = row.try_get("applied_at").map_err(AdapterError::Sqlx)?;
            match applied {
                None => Ok(None),
                Some(s) => {
                    let ts = s
                        .parse::<Rfc3339Timestamp>()
                        .map_err(|e| AdapterError::Parse(e.to_string()))
                        .map_err(StorageError::from)?;
                    Ok(Some(ts))
                }
            }
        }
    }
}

/// Mark a plan applied. Fails if missing or already applied.
pub(crate) async fn mark_restore_plan_applied(
    pool: &SqlitePool,
    plan_id: &UuidV7,
    applied_at: &Rfc3339Timestamp,
) -> Result<(), StorageError> {
    let id_blob = uuid_to_blob(*plan_id);
    let applied_str = applied_at.to_string();

    let result = sqlx::query(
        r"UPDATE restore_plans
          SET applied_at = ?2
          WHERE id = ?1 AND applied_at IS NULL",
    )
    .bind(&id_blob)
    .bind(&applied_str)
    .execute(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    if result.rows_affected() == 1 {
        return Ok(());
    }

    // Distinguish missing vs already applied.
    let exists = sqlx::query(r"SELECT 1 AS ok FROM restore_plans WHERE id = ?1")
        .bind(&id_blob)
        .fetch_optional(pool)
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;
    if exists.is_none() {
        return Err(StorageError::NotFound);
    }
    Err(StorageError::Conflict(format!(
        "restore plan {plan_id} already applied"
    )))
}
