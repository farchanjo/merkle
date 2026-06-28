//! `put_secret` / `get_secret_by_handle` / `list_secrets` / `delete_secret`
//! / `search_secrets` / `check_fts5_consistency`.

use merkle_domain_secret_storage::{Secret, secret_version::SecretVersion};
use merkle_ports::{
    RankedSearchParams, RankedSearchResult, RankedSecret, SearchHighlight, SecretFilter,
    StorageError,
};
use merkle_types::{Handle, NamespaceId, SecretId};
use sqlx::{Row, SqliteConnection, SqlitePool};

use crate::error::AdapterError;
use crate::mappers::{id_to_blob, row_to_secret, row_to_secret_version, uuid_to_blob};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Upsert a single `SecretVersion` row, using `parent_id` as the canonical
/// `secret_id` (overrides `v.secret_id` which may carry a placeholder value
/// set before `Secret::new` generated the real identity).
///
/// Runs against a caller-supplied connection (typically the open transaction in
/// [`put_secret`]) so the version writes commit atomically with the parent row.
async fn upsert_version_with_parent(
    conn: &mut SqliteConnection,
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
    .execute(&mut *conn)
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Flatten a JSON tags array `[{"key":"env","value":"prod"},...]`
/// to the space-separated `"env:prod ..."` string stored in `tags_text`.
fn flatten_tags_json(tags_json: &str) -> String {
    let tags: Vec<merkle_types::Tag> = serde_json::from_str(tags_json).unwrap_or_default();
    tags.iter()
        .map(|t| format!("{}:{}", t.key, t.value))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

/// Upsert the `secrets` row for `secret` against an open connection.
///
/// Materializes `namespace_label` from the handle so the FTS5 triggers index
/// the real namespace label (the `COALESCE(new.namespace_label, …)` fallback
/// only fires when the column is `NULL`, never for the `''` default).
async fn upsert_secret_row(
    conn: &mut SqliteConnection,
    secret: &Secret,
) -> Result<(), AdapterError> {
    let id_blob = id_to_blob!(secret.id);
    let ns_blob = id_to_blob!(secret.namespace_id);
    let handle_str = secret.handle.to_string();
    let name_str = secret.handle.secret_name().to_string();
    let namespace_label = secret.handle.namespace().to_string();
    let category_str = secret.category.to_string();
    let sensitivity_str = secret.sensitivity.to_string();
    let public_metadata_json =
        serde_json::to_string(&secret.public_metadata).map_err(AdapterError::Json)?;
    let tags_json = serde_json::to_string(&secret.tags).map_err(AdapterError::Json)?;
    let tags_text = flatten_tags_json(&tags_json);
    let description = secret
        .public_metadata
        .description
        .as_deref()
        .unwrap_or("")
        .to_owned();
    let current_version_id_blob = uuid_to_blob(secret.current_version_id().inner());
    let created_at = secret.created_at.to_string();

    sqlx::query(
        r"INSERT INTO secrets
            (id, namespace_id, handle, name, category, sensitivity,
             public_metadata_json, tags_json, tags_text, description,
             current_version_id, created_at, namespace_label)
          VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
          ON CONFLICT(id) DO UPDATE SET
              handle               = excluded.handle,
              name                 = excluded.name,
              sensitivity          = excluded.sensitivity,
              public_metadata_json = excluded.public_metadata_json,
              tags_json            = excluded.tags_json,
              tags_text            = excluded.tags_text,
              description          = excluded.description,
              current_version_id   = excluded.current_version_id,
              namespace_label      = excluded.namespace_label",
    )
    .bind(&id_blob)
    .bind(&ns_blob)
    .bind(&handle_str)
    .bind(&name_str)
    .bind(&category_str)
    .bind(&sensitivity_str)
    .bind(&public_metadata_json)
    .bind(&tags_json)
    .bind(&tags_text)
    .bind(&description)
    .bind(&current_version_id_blob)
    .bind(&created_at)
    .bind(&namespace_label)
    .execute(&mut *conn)
    .await?;

    Ok(())
}

/// Upsert a [`Secret`] and all its [`SecretVersion`]s atomically.
///
/// The parent row and every version write share ONE transaction: a concurrent
/// reader never observes the `secrets` row before its versions, and any failure
/// rolls the whole batch back rather than leaving a dangling parent.
pub(crate) async fn put_secret(pool: &SqlitePool, secret: &Secret) -> Result<(), StorageError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    upsert_secret_row(&mut tx, secret)
        .await
        .map_err(StorageError::from)?;

    // We override `secret_id` in the write path to guarantee it always matches
    // the parent `Secret::id` — the domain type doesn't enforce this at
    // construction time, so a newly-created Secret may carry a placeholder id
    // in the initial version's `secret_id` field.
    for version in secret.versions() {
        upsert_version_with_parent(&mut tx, version, &secret.id)
            .await
            .map_err(StorageError::from)?;
    }

    tx.commit()
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

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
        conditions.push(format!("s.handle LIKE ?{bind_idx} ESCAPE '\\'"));
        bind_idx += 1;
    }

    if filter.expires_before.is_some() {
        conditions.push(format!(
            "json_extract(s.public_metadata_json, '$.expires_at') < ?{bind_idx}"
        ));
        bind_idx += 1;
    }

    // The tag filter is applied row-by-row in Rust below (SQL JSON array
    // intersection is verbose in SQLite). Pushing a SQL `LIMIT` here would
    // truncate the result set BEFORE the tag filter runs, silently dropping
    // matching rows. So only let SQL apply the limit when there is no tag
    // filter; otherwise we fetch all candidates and truncate AFTER filtering.
    let limit_clause = match (filter.limit, filter.tag_match.is_none()) {
        (Some(l), true) => format!(" LIMIT {l}"),
        _ => String::new(),
    };

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
        // Escape LIKE metacharacters in the literal text BEFORE translating the
        // user's `*` glob to SQL `%`, so a literal `%` or `_` in the pattern
        // cannot act as a wildcard and enumerate unrelated handles. Backslash
        // is escaped first to avoid double-escaping; the SQL uses ESCAPE '\'.
        let like_pattern = pattern
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
            .replace('*', "%");
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

    // When a tag filter is present the SQL query did NOT apply the limit (see
    // `limit_clause` above), so enforce it here — AFTER tag matching — so the
    // page reflects the filtered set rather than a pre-filter truncation.
    if filter.tag_match.is_some() {
        if let Some(limit) = filter.limit {
            secrets.truncate(limit as usize);
        }
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

// ---------------------------------------------------------------------------
// Ranked BM25 search (ADR-0027)
// ---------------------------------------------------------------------------

/// Ranked query template per ADR-0027 §Index Schema.
///
/// Weight vector `(10.0, 5.0, 3.0, 2.0, 1.0)` maps positionally to the
/// `CREATE VIRTUAL TABLE secrets_fts` column declaration order:
///   name (pos 0, weight 10.0), tags_text (pos 1, weight 5.0),
///   description (pos 2, weight 3.0), category (pos 3, weight 2.0),
///   namespace_label (pos 4, weight 1.0).
///
/// `ORDER BY bm25_score ASC` because SQLite BM25 returns negative values;
/// most-negative = best match.
const RANKED_SQL: &str = r"
    SELECT
        s.id, s.namespace_id, s.handle, s.category, s.sensitivity,
        s.public_metadata_json, s.tags_json, s.current_version_id, s.created_at,
        bm25(secrets_fts, 10.0, 5.0, 3.0, 2.0, 1.0)     AS bm25_score,
        highlight(secrets_fts, 0, '<b>', '</b>')           AS hl_name,
        highlight(secrets_fts, 1, '<b>', '</b>')           AS hl_tags,
        snippet(secrets_fts, 2, '<b>', '</b>', '...', 20) AS hl_description,
        highlight(secrets_fts, 3, '<b>', '</b>')           AS hl_category,
        highlight(secrets_fts, 4, '<b>', '</b>')           AS hl_namespace_label
    FROM secrets s
    JOIN secrets_fts f ON f.rowid = s.rowid
    WHERE
        s.namespace_id = ?1
        AND secrets_fts MATCH ?2
    ORDER BY bm25_score ASC
    LIMIT ?3
    OFFSET ?4
";

/// Count query (for `total` and `has_more`) — same filter, no projection.
const COUNT_SQL: &str = r"
    SELECT COUNT(*) AS cnt
    FROM secrets s
    JOIN secrets_fts f ON f.rowid = s.rowid
    WHERE
        s.namespace_id = ?1
        AND secrets_fts MATCH ?2
";

/// Build the highlight list for a single result row; skips empty snippets.
fn build_highlights(row: &sqlx::sqlite::SqliteRow) -> Vec<SearchHighlight> {
    let fields = [
        ("name", "hl_name"),
        ("tags", "hl_tags"),
        ("description", "hl_description"),
        ("category", "hl_category"),
        ("namespace_label", "hl_namespace_label"),
    ];
    fields
        .iter()
        .filter_map(|(field, col)| {
            let snippet: Option<String> = row.try_get(*col).ok()?;
            let snippet = snippet?;
            if snippet.is_empty() {
                None
            } else {
                Some(SearchHighlight {
                    field: (*field).to_owned(),
                    snippet,
                })
            }
        })
        .collect()
}

/// Execute a weighted BM25 ranked FTS5 search (ADR-0027).
pub(crate) async fn search_secrets(
    pool: &SqlitePool,
    namespace_id: &NamespaceId,
    params: RankedSearchParams,
) -> Result<RankedSearchResult, StorageError> {
    let ns_blob = id_to_blob!(namespace_id);

    // Count total matches for has_more / total fields.
    let count_row = sqlx::query(COUNT_SQL)
        .bind(&ns_blob)
        .bind(&params.fts_query)
        .fetch_one(pool)
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;
    let total: i64 = count_row
        .try_get("cnt")
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;
    let total = u32::try_from(total).unwrap_or(u32::MAX);

    let has_more = total > params.offset.saturating_add(params.limit);

    let rows = sqlx::query(RANKED_SQL)
        .bind(&ns_blob)
        .bind(&params.fts_query)
        .bind(i64::from(params.limit))
        .bind(i64::from(params.offset))
        .fetch_all(pool)
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    let mut items = Vec::with_capacity(rows.len());
    for (page_idx, row) in rows.iter().enumerate() {
        let id_bytes: Vec<u8> = row
            .try_get("id")
            .map_err(AdapterError::Sqlx)
            .map_err(StorageError::from)?;
        let versions = load_versions_for_secret(pool, &id_bytes).await?;
        let secret = row_to_secret(row, &versions).map_err(StorageError::from)?;

        let score: f64 = row
            .try_get("bm25_score")
            .map_err(AdapterError::Sqlx)
            .map_err(StorageError::from)?;

        let highlights = build_highlights(row);

        items.push(RankedSecret {
            secret,
            score,
            bm25_rank: u32::try_from(page_idx + 1).unwrap_or(u32::MAX),
            highlights,
        });
    }

    Ok(RankedSearchResult {
        items,
        total,
        has_more,
    })
}

// ---------------------------------------------------------------------------
// FTS5 consistency check (ADR-0027 doctor)
// ---------------------------------------------------------------------------

/// Authoritative column list per ADR-0027 §Index Schema (declaration order).
/// `tags_text` is the materialized column name that maps to the `tags` weight
/// position (5.0). Using a real column name keeps content table back-reads valid.
const EXPECTED_FTS5_COLUMNS: [&str; 5] = [
    "name",
    "tags_text",
    "description",
    "category",
    "namespace_label",
];

/// Check FTS5 schema consistency: column list, orphan detection, privacy audit.
pub(crate) async fn check_fts5_consistency(pool: &SqlitePool) -> Result<(), StorageError> {
    // 1. Validate column list against the authoritative spec.
    let col_rows = sqlx::query("SELECT name FROM pragma_table_info('secrets_fts') ORDER BY cid")
        .fetch_all(pool)
        .await
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;

    let actual_cols: Vec<String> = col_rows
        .iter()
        .filter_map(|r| r.try_get::<String, _>("name").ok())
        .collect();

    let expected: Vec<String> = EXPECTED_FTS5_COLUMNS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

    if actual_cols != expected {
        return Err(StorageError::Fts5Inconsistent(format!(
            "column mismatch: expected {expected:?}, got {actual_cols:?}"
        )));
    }

    // 2. Ensure every secret has a matching FTS5 row.
    let orphan_row = sqlx::query(
        "SELECT COUNT(*) AS cnt FROM secrets s
         WHERE NOT EXISTS (SELECT 1 FROM secrets_fts f WHERE f.rowid = s.rowid)",
    )
    .fetch_one(pool)
    .await
    .map_err(AdapterError::Sqlx)
    .map_err(StorageError::from)?;
    let orphan_cnt: i64 = orphan_row
        .try_get("cnt")
        .map_err(AdapterError::Sqlx)
        .map_err(StorageError::from)?;
    if orphan_cnt > 0 {
        return Err(StorageError::Fts5Inconsistent(format!(
            "{orphan_cnt} secret(s) have no matching FTS5 row"
        )));
    }

    // 3. Privacy audit: the FTS5 shadow content table only stores tokens; the
    //    content=secrets directive means original text is read from the secrets
    //    table at query time. There is no separate plaintext stored in FTS5
    //    shadow tables for a content table — only term/rowid mappings.
    //    We additionally assert no private column names appear as FTS5 columns.
    let forbidden = [
        "private_blob",
        "ciphertext",
        "nonce",
        "aead_tag",
        "associated_data",
    ];
    for col in &actual_cols {
        if forbidden.contains(&col.as_str()) {
            return Err(StorageError::Fts5Inconsistent(format!(
                "private field '{col}' is indexed in secrets_fts (privacy violation)"
            )));
        }
    }

    Ok(())
}
