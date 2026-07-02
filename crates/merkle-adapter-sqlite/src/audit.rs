//! `append_audit_entry` / `read_audit` / `pinned_head` / `update_pinned_head`.
//!
//! ADR-0009 requirements enforced here:
//! - `commit_audit_entry` writes the entry AND the MAC-authenticated pinned head
//!   in a single `BEGIN IMMEDIATE` transaction — the atomic hot path. A crash
//!   can never leave the head un-authenticated (`hmac_head` NULL).
//! - `append_audit_entry` (entry + NULL-MAC head) remains for callers that pin
//!   the head MAC separately via `update_pinned_head`.
//! - Append-only discipline is additionally enforced at the SQL trigger level
//!   (see `001_initial.sql`).

use merkle_domain_audit_compliance::{AuditBaseline, AuditEntry, AuditQuery, PinnedHead};
use merkle_ports::{AuditSnapshot, StorageError};
use sqlx::SqlitePool;

use crate::error::AdapterError;
use crate::mappers::{row_to_audit_baseline, row_to_audit_entry, row_to_pinned_head, uuid_to_blob};
use merkle_types::Rfc3339Timestamp;

/// Insert a single [`AuditEntry`] row inside an open transaction.
async fn insert_entry_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
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
    .execute(&mut **tx)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;
    Ok(())
}

/// Upsert the `pinned_head` singleton row inside an open transaction.
///
/// `hmac_head` is written verbatim from `head` — `None` resets it to NULL,
/// `Some` writes the real head-commitment MAC.
async fn upsert_pinned_head_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    head_hash: &str,
    head_seq: i64,
    head_id_blob: &[u8],
    updated_at: &str,
    hmac_head: Option<&str>,
) -> Result<(), StorageError> {
    sqlx::query(
        r"INSERT INTO pinned_head (singleton, head_hash, head_seq, head_id, updated_at, hmac_head)
          VALUES (1, ?1, ?2, ?3, ?4, ?5)
          ON CONFLICT(singleton) DO UPDATE SET
              head_hash  = excluded.head_hash,
              head_seq   = excluded.head_seq,
              head_id    = excluded.head_id,
              updated_at = excluded.updated_at,
              hmac_head  = excluded.hmac_head",
    )
    .bind(head_hash)
    .bind(head_seq)
    .bind(head_id_blob)
    .bind(updated_at)
    .bind(hmac_head)
    .execute(&mut **tx)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;
    Ok(())
}

/// Append one [`AuditEntry`] and reset the pinned head, leaving `hmac_head`
/// NULL (the entry alone cannot carry the keyed head MAC).
///
/// Prefer [`commit_audit_entry`] on the hot path: this variant leaves the head
/// un-authenticated until a later `update_pinned_head`, which fails closed if a
/// crash lands in between. It remains for callers (tests) that pin the MAC
/// separately.
///
/// Uses `BEGIN IMMEDIATE` to prevent concurrent writers racing on the
/// `pinned_head` singleton row (ADR-0009 Amendment — chain-head pinning).
pub(crate) async fn append_audit_entry(
    pool: &SqlitePool,
    entry: &AuditEntry,
) -> Result<(), StorageError> {
    let head_hash = entry.current_hash.to_string();
    let head_seq = i64::try_from(entry.seq).unwrap_or(i64::MAX);
    let head_id_blob = uuid_to_blob(entry.id.inner());
    let updated_at = Rfc3339Timestamp::now().to_string();

    let mut tx = pool
        .begin()
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;
    insert_entry_tx(&mut tx, entry).await?;
    upsert_pinned_head_tx(&mut tx, &head_hash, head_seq, &head_id_blob, &updated_at, None).await?;
    tx.commit()
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;
    Ok(())
}

/// Append one [`AuditEntry`] and pin its already-MAC'd `head` in a SINGLE
/// transaction.
///
/// This closes the crash-consistency window of the append-then-update pattern:
/// `hmac_head` is written with its real MAC in the same commit as the entry, so
/// a crash can never leave the pinned head un-authenticated (`hmac_head` NULL),
/// which would otherwise fail verification closed (`HeadMacMismatch`) until the
/// next successful write. `BEGIN IMMEDIATE` serializes concurrent writers.
pub(crate) async fn commit_audit_entry(
    pool: &SqlitePool,
    entry: &AuditEntry,
    head: &PinnedHead,
) -> Result<(), StorageError> {
    let head_hash = head.head_hash.to_string();
    let head_seq = i64::try_from(head.head_seq).unwrap_or(i64::MAX);
    let head_id_blob = uuid_to_blob(head.head_id.inner());
    let updated_at = head.updated_at.to_string();
    let hmac_head = head.hmac_head.map(|h| h.to_string());

    let mut tx = pool
        .begin()
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;
    insert_entry_tx(&mut tx, entry).await?;
    upsert_pinned_head_tx(
        &mut tx,
        &head_hash,
        head_seq,
        &head_id_blob,
        &updated_at,
        hmac_head.as_deref(),
    )
    .await?;
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

/// Read every persisted audit entry, in ascending `seq` order, within an open
/// transaction.
///
/// Used by [`audit_snapshot`]. Equivalent to `read_audit(pool,
/// &AuditQuery::default())` — the snapshot always reads the full unfiltered
/// log, so no dynamic `WHERE`-clause construction is needed here; the SQL
/// text matches what [`read_audit`] would generate for a default query.
async fn read_all_entries_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<AuditEntry>, StorageError> {
    let rows = sqlx::query(
        "SELECT id, seq, ts, namespace_id, caller_program, op, outcome,
                denial_reason, handle, sensitivity, prev_hash, current_hash, hmac
         FROM audit_entries ORDER BY seq ASC",
    )
    .fetch_all(&mut **tx)
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
        "SELECT head_hash, head_seq, head_id, updated_at, hmac_head \
         FROM pinned_head WHERE singleton = 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    row.as_ref()
        .map(row_to_pinned_head)
        .transpose()
        .map_err(StorageError::from)
}

/// Fetch the current pinned chain head within an open transaction.
///
/// Used by [`audit_snapshot`] so the read observes the same in-flight
/// transaction as the entries and baseline reads (gap #10 — audit-verify
/// snapshot isolation). Uses the exact same SQL and row-mapping as
/// [`pinned_head`].
async fn pinned_head_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Option<PinnedHead>, StorageError> {
    let row = sqlx::query(
        "SELECT head_hash, head_seq, head_id, updated_at, hmac_head \
         FROM pinned_head WHERE singleton = 1",
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    row.as_ref()
        .map(row_to_pinned_head)
        .transpose()
        .map_err(StorageError::from)
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
    let hmac_head = head.hmac_head.map(|h| h.to_string());

    sqlx::query(
        r"INSERT INTO pinned_head (singleton, head_hash, head_seq, head_id, updated_at, hmac_head)
          VALUES (1, ?1, ?2, ?3, ?4, ?5)
          ON CONFLICT(singleton) DO UPDATE SET
              head_hash  = excluded.head_hash,
              head_seq   = excluded.head_seq,
              head_id    = excluded.head_id,
              updated_at = excluded.updated_at,
              hmac_head  = excluded.hmac_head",
    )
    .bind(&head_hash)
    .bind(head_seq)
    .bind(&head_id_blob)
    .bind(&updated_at)
    .bind(&hmac_head)
    .execute(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    Ok(())
}

/// Fetch the trusted audit baseline singleton, or `None` when none is pinned
/// (ADR-0029).
pub(crate) async fn audit_baseline(
    pool: &SqlitePool,
) -> Result<Option<AuditBaseline>, StorageError> {
    let row = sqlx::query(
        "SELECT baseline_seq, baseline_id, baseline_hash, entry_count, reason, created_at, hmac \
         FROM audit_baseline WHERE singleton = 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    row.as_ref()
        .map(row_to_audit_baseline)
        .transpose()
        .map_err(StorageError::from)
}

/// Fetch the trusted audit baseline singleton within an open transaction.
///
/// Used by [`audit_snapshot`] so the read observes the same in-flight
/// transaction as the entries and pinned-head reads (gap #10 — audit-verify
/// snapshot isolation). Uses the exact same SQL and row-mapping as
/// [`audit_baseline`].
async fn audit_baseline_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Option<AuditBaseline>, StorageError> {
    let row = sqlx::query(
        "SELECT baseline_seq, baseline_id, baseline_hash, entry_count, reason, created_at, hmac \
         FROM audit_baseline WHERE singleton = 1",
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    row.as_ref()
        .map(row_to_audit_baseline)
        .transpose()
        .map_err(StorageError::from)
}

/// Upsert the trusted audit baseline singleton (ADR-0029).
///
/// Recovery adds/updates this checkpoint row; it never rewrites `audit_entries`,
/// preserving the append-only discipline.
pub(crate) async fn set_audit_baseline(
    pool: &SqlitePool,
    baseline: &AuditBaseline,
) -> Result<(), StorageError> {
    let baseline_seq = i64::try_from(baseline.baseline_seq).unwrap_or(i64::MAX);
    let baseline_id_blob = uuid_to_blob(baseline.baseline_id.inner());
    let baseline_hash = baseline.baseline_hash.to_string();
    let entry_count = i64::try_from(baseline.entry_count).unwrap_or(i64::MAX);
    let created_at = baseline.created_at.to_string();
    let hmac = baseline.hmac.map(|h| h.to_string());

    sqlx::query(
        r"INSERT INTO audit_baseline
            (singleton, baseline_seq, baseline_id, baseline_hash, entry_count, reason, created_at, hmac)
          VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)
          ON CONFLICT(singleton) DO UPDATE SET
              baseline_seq  = excluded.baseline_seq,
              baseline_id   = excluded.baseline_id,
              baseline_hash = excluded.baseline_hash,
              entry_count   = excluded.entry_count,
              reason        = excluded.reason,
              created_at    = excluded.created_at,
              hmac          = excluded.hmac",
    )
    .bind(baseline_seq)
    .bind(&baseline_id_blob)
    .bind(&baseline_hash)
    .bind(entry_count)
    .bind(&baseline.reason)
    .bind(&created_at)
    .bind(&hmac)
    .execute(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;

    Ok(())
}

/// Read the full audit log, the pinned head, and the trusted baseline as ONE
/// consistent snapshot (gap #10 — audit-verify snapshot isolation).
///
/// `read_audit` + `pinned_head` + `audit_baseline` are otherwise three
/// independent round-trips against the pool; a concurrent
/// [`commit_audit_entry`] landing between them can pair entries from before
/// the write with a pinned head from after (or vice-versa), producing a false
/// `TruncationDetected` / `HeadHashMismatch` in the chain verifier. Opening a
/// single transaction and reading all three within it closes that interleave
/// window: SQLite's WAL mode gives a transaction a consistent view of the
/// database as of its first read statement, so every read below observes the
/// exact same point-in-time state regardless of concurrent writers.
///
/// This is a read-only snapshot, so a plain (deferred) transaction is used —
/// unlike the write path (`commit_audit_entry`), there is no need for
/// `BEGIN IMMEDIATE` writer-serialization here.
pub(crate) async fn audit_snapshot(pool: &SqlitePool) -> Result<AuditSnapshot, StorageError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    let entries = read_all_entries_tx(&mut tx).await?;
    let pinned_head = pinned_head_tx(&mut tx).await?;
    let baseline = audit_baseline_tx(&mut tx).await?;

    tx.commit()
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    Ok(AuditSnapshot {
        entries,
        pinned_head,
        baseline,
    })
}
