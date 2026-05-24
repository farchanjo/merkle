//! `append_audit_entry` / `read_audit` / `pinned_head` / `update_pinned_head`.
//!
//! ADR-0009 requirements enforced here:
//! - `append_audit_entry` + `update_pinned_head` share a single `BEGIN IMMEDIATE`
//!   transaction to guarantee atomicity.
//! - Append-only discipline is additionally enforced at the SQL trigger level
//!   (see `001_initial.sql`).

use merkle_domain_audit_compliance::{AuditEntry, AuditQuery, PinnedHead};
use merkle_ports::StorageError;
use sqlx::{Row, SqlitePool};

use crate::error::AdapterError;
use crate::mappers::{blob_to_audit_entry_id, row_to_audit_entry, uuid_to_blob};
use merkle_types::{Blake3Hash, Rfc3339Timestamp};

/// Append one [`AuditEntry`] and atomically update the pinned head.
///
/// Uses `BEGIN IMMEDIATE` to prevent concurrent writers racing on the
/// `pinned_head` singleton row (ADR-0009 Amendment — chain-head pinning).
pub(crate) async fn append_audit_entry(
    pool: &SqlitePool,
    entry: &AuditEntry,
) -> Result<(), StorageError> {
    let id_blob = uuid_to_blob(entry.id.inner());
    let seq = i64::try_from(entry.seq).unwrap_or(i64::MAX);
    let ts = entry.ts.to_string();
    let ns_blob = uuid_to_blob(entry.namespace_id.inner());
    let op = entry.op.to_string();
    let outcome = entry.outcome.to_string();
    let denial_reason = entry.denial_reason.as_ref().map(ToString::to_string);
    let handle = entry.handle.as_ref().map(ToString::to_string);
    let sensitivity = entry.sensitivity.map(|s| s.to_string());
    let prev_hash = entry.prev_hash.map(|h| h.to_string());
    let current_hash = entry.current_hash.to_string();
    let hmac = entry.hmac.map(|h| h.to_string());

    // Pinned head values for the atomic update.
    let head_hash = current_hash.clone();
    let head_seq = seq;
    let head_id_blob = id_blob.clone();
    let updated_at = Rfc3339Timestamp::now().to_string();

    // BEGIN IMMEDIATE locks the database for writing immediately, preventing
    // a concurrent writer from interleaving between entry insert and head update.
    let mut tx = pool
        .begin()
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    sqlx::query(
        r"INSERT INTO audit_entries
            (id, seq, ts, namespace_id, caller_program, op, outcome,
             denial_reason, handle, sensitivity, prev_hash, current_hash, hmac)
          VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
    )
    .bind(&id_blob)
    .bind(seq)
    .bind(&ts)
    .bind(&ns_blob)
    .bind(&entry.caller_program)
    .bind(&op)
    .bind(&outcome)
    .bind(&denial_reason)
    .bind(&handle)
    .bind(&sensitivity)
    .bind(&prev_hash)
    .bind(&current_hash)
    .bind(&hmac)
    .execute(&mut *tx)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    // Atomically upsert the pinned_head singleton row.
    sqlx::query(
        r"INSERT INTO pinned_head (singleton, head_hash, head_seq, head_id, updated_at)
          VALUES (1, ?1, ?2, ?3, ?4)
          ON CONFLICT(singleton) DO UPDATE SET
              head_hash  = excluded.head_hash,
              head_seq   = excluded.head_seq,
              head_id    = excluded.head_id,
              updated_at = excluded.updated_at",
    )
    .bind(&head_hash)
    .bind(head_seq)
    .bind(&head_id_blob)
    .bind(&updated_at)
    .execute(&mut *tx)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    tx.commit()
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;
    Ok(())
}

/// Read audit entries matching the given [`AuditQuery`].
pub(crate) async fn read_audit(
    pool: &SqlitePool,
    query: &AuditQuery,
) -> Result<Vec<AuditEntry>, StorageError> {
    let mut conditions: Vec<String> = Vec::new();
    let mut bind_idx: u32 = 1;

    if query.op.is_some() {
        conditions.push(format!("op = ?{bind_idx}"));
        bind_idx += 1;
    }
    if query.outcome.is_some() {
        conditions.push(format!("outcome = ?{bind_idx}"));
        bind_idx += 1;
    }
    if query.namespace_id.is_some() {
        conditions.push(format!("namespace_id = ?{bind_idx}"));
        bind_idx += 1;
    }
    if query.handle.is_some() {
        conditions.push(format!("handle = ?{bind_idx}"));
        bind_idx += 1;
    }
    if query.sensitivity.is_some() {
        conditions.push(format!("sensitivity = ?{bind_idx}"));
        bind_idx += 1;
    }
    if query.from.is_some() {
        conditions.push(format!("ts >= ?{bind_idx}"));
        bind_idx += 1;
    }
    if query.to.is_some() {
        conditions.push(format!("ts <= ?{bind_idx}"));
        bind_idx += 1;
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let limit_clause = query
        .limit
        .map(|l| format!(" LIMIT {l}"))
        .unwrap_or_default();

    let _ = bind_idx; // consumed above

    let sql = format!(
        "SELECT id, seq, ts, namespace_id, caller_program, op, outcome,
                denial_reason, handle, sensitivity, prev_hash, current_hash, hmac
         FROM audit_entries {where_clause} ORDER BY seq ASC{limit_clause}"
    );

    let mut q = sqlx::query(&sql);

    if let Some(op) = query.op {
        q = q.bind(op.to_string());
    }
    if let Some(outcome) = query.outcome {
        q = q.bind(outcome.to_string());
    }
    if let Some(ref ns_id) = query.namespace_id {
        q = q.bind(uuid_to_blob(ns_id.inner()));
    }
    if let Some(ref h) = query.handle {
        q = q.bind(h.to_string());
    }
    if let Some(sens) = query.sensitivity {
        q = q.bind(sens.to_string());
    }
    if let Some(ref from) = query.from {
        q = q.bind(from.to_string());
    }
    if let Some(ref to) = query.to {
        q = q.bind(to.to_string());
    }

    let rows = q
        .fetch_all(pool)
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    rows.iter()
        .map(|r| row_to_audit_entry(r).map_err(StorageError::from))
        .collect()
}

/// Fetch the current pinned chain head, returning `None` on an empty vault.
pub(crate) async fn pinned_head(pool: &SqlitePool) -> Result<Option<PinnedHead>, StorageError> {
    let row = sqlx::query(
        "SELECT head_hash, head_seq, head_id, updated_at FROM pinned_head WHERE singleton = 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    let Some(r) = row else {
        return Ok(None);
    };

    let head_hash_str: String = r
        .try_get("head_hash")
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;
    let head_hash = head_hash_str
        .parse::<Blake3Hash>()
        .map_err(|e| StorageError::Constraint(e.to_string()))?;

    let head_seq: i64 = r
        .try_get("head_seq")
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    let head_id_bytes: Vec<u8> = r
        .try_get("head_id")
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;
    let head_id = blob_to_audit_entry_id(&head_id_bytes).map_err(StorageError::from)?;

    let updated_at_str: String = r
        .try_get("updated_at")
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;
    let updated_at = updated_at_str
        .parse::<Rfc3339Timestamp>()
        .map_err(|e| StorageError::Constraint(e.to_string()))?;

    Ok(Some(PinnedHead::new(
        head_hash,
        u64::try_from(head_seq).unwrap_or(0),
        head_id,
        updated_at,
    )))
}

/// Overwrite the pinned chain head directly (used by the chain verifier /
/// recovery paths; normal writes use the atomic path in `append_audit_entry`).
pub(crate) async fn update_pinned_head(
    pool: &SqlitePool,
    head: &PinnedHead,
) -> Result<(), StorageError> {
    let head_hash = head.head_hash.to_string();
    let head_seq = i64::try_from(head.head_seq).unwrap_or(i64::MAX);
    let head_id_blob = uuid_to_blob(head.head_id.inner());
    let updated_at = head.updated_at.to_string();

    sqlx::query(
        r"INSERT INTO pinned_head (singleton, head_hash, head_seq, head_id, updated_at)
          VALUES (1, ?1, ?2, ?3, ?4)
          ON CONFLICT(singleton) DO UPDATE SET
              head_hash  = excluded.head_hash,
              head_seq   = excluded.head_seq,
              head_id    = excluded.head_id,
              updated_at = excluded.updated_at",
    )
    .bind(&head_hash)
    .bind(head_seq)
    .bind(&head_id_blob)
    .bind(&updated_at)
    .execute(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    Ok(())
}
