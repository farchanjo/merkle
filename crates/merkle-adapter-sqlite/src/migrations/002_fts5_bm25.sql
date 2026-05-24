-- Migration 002: Weighted BM25 FTS5 schema + UPDATE trigger
-- ADR-0027: replaces the wrong-column FTS5 virtual table from migration 001
-- with the authoritative schema (name, tags_text, description, category, namespace_label)
-- and fixes the missing UPDATE trigger gap.
--
-- Column declaration order is LOAD-BEARING: it maps directly to the
-- bm25(secrets_fts, 10.0, 5.0, 3.0, 2.0, 1.0) weight-vector positions.
-- DO NOT reorder columns without updating every bm25() call site.
--
-- All five FTS5 column names must match real columns on `secrets` because
-- the FTS5 content table back-reads them for highlight() and snippet().
-- description is materialized from public_metadata_json at write time.
-- tags_text is a space-separated "key:value" flattening of tags_json.
-- namespace_label is denormalized from namespaces.label.

-- ------------------------------------------------------------------
-- Step 1: drop the old FTS5 virtual table and its triggers.
-- SQLite drops associated shadow tables automatically when the virtual
-- table is dropped.
-- ------------------------------------------------------------------

DROP TRIGGER IF EXISTS secrets_ai;
DROP TRIGGER IF EXISTS secrets_ad;
DROP TABLE  IF EXISTS secrets_fts;

-- ------------------------------------------------------------------
-- Step 2: add the materialized columns required by the content table.
--
-- `name`            — last path segment of the handle URI.
-- `tags_text`       — space-separated "key:value" pairs from tags_json.
-- `description`     — extracted from public_metadata_json $.description.
-- `namespace_label` — denormalized from namespaces.label.
--
-- All four must be real columns so that the FTS5 content table can
-- back-read them for highlight() and snippet() projections.
-- ------------------------------------------------------------------

ALTER TABLE secrets ADD COLUMN name           TEXT NOT NULL DEFAULT '';
ALTER TABLE secrets ADD COLUMN tags_text       TEXT NOT NULL DEFAULT '';
ALTER TABLE secrets ADD COLUMN description     TEXT NOT NULL DEFAULT '';
ALTER TABLE secrets ADD COLUMN namespace_label TEXT NOT NULL DEFAULT '';

-- Backfill name: extract last slash-delimited path segment from handle.
UPDATE secrets
SET name = SUBSTR(handle, INSTR(handle, '/') +
               INSTR(SUBSTR(handle, INSTR(handle, '/') + 1), '/') + 1)
WHERE name = '';

-- Fallback: if the handle has only one slash segment, use everything after it.
UPDATE secrets
SET name = SUBSTR(handle, INSTR(handle, '/') + 1)
WHERE name = '';

-- Backfill description from the JSON metadata blob.
UPDATE secrets
SET description = COALESCE(json_extract(public_metadata_json, '$.description'), '')
WHERE description = '';

-- Backfill namespace_label from the namespaces table.
UPDATE secrets
SET namespace_label = (
    SELECT label FROM namespaces WHERE namespaces.id = secrets.namespace_id
)
WHERE namespace_label = '';

-- ------------------------------------------------------------------
-- Step 3: recreate secrets_fts per ADR-0027 §Index Schema.
-- Column order: name, tags_text, description, category, namespace_label.
-- Column names MUST match real columns in `secrets` for content table
-- back-reading used by highlight() and snippet() at query time.
-- ------------------------------------------------------------------

CREATE VIRTUAL TABLE IF NOT EXISTS secrets_fts USING fts5(
    name,
    tags_text,
    description,
    category,
    namespace_label,
    content='secrets',
    content_rowid='rowid',
    tokenize='porter unicode61 remove_diacritics 2'
);

-- ------------------------------------------------------------------
-- Step 4: INSERT trigger — fires after every new row in `secrets`.
-- ------------------------------------------------------------------

CREATE TRIGGER IF NOT EXISTS secrets_fts_ai AFTER INSERT ON secrets BEGIN
    INSERT INTO secrets_fts(rowid, name, tags_text, description, category, namespace_label)
    VALUES (
        new.rowid,
        new.name,
        COALESCE(new.tags_text, ''),
        COALESCE(new.description, ''),
        new.category,
        COALESCE(new.namespace_label, (SELECT label FROM namespaces WHERE id = new.namespace_id))
    );
END;

-- ------------------------------------------------------------------
-- Step 5: UPDATE trigger — the missing gap from migration 001.
-- Removes the stale FTS5 entry and inserts the refreshed one.
-- ------------------------------------------------------------------

CREATE TRIGGER IF NOT EXISTS secrets_fts_au AFTER UPDATE ON secrets BEGIN
    INSERT INTO secrets_fts(secrets_fts, rowid, name, tags_text, description, category, namespace_label)
    VALUES (
        'delete',
        old.rowid,
        old.name,
        COALESCE(old.tags_text, ''),
        COALESCE(old.description, ''),
        old.category,
        COALESCE(old.namespace_label, (SELECT label FROM namespaces WHERE id = old.namespace_id))
    );

    INSERT INTO secrets_fts(rowid, name, tags_text, description, category, namespace_label)
    VALUES (
        new.rowid,
        new.name,
        COALESCE(new.tags_text, ''),
        COALESCE(new.description, ''),
        new.category,
        COALESCE(new.namespace_label, (SELECT label FROM namespaces WHERE id = new.namespace_id))
    );
END;

-- ------------------------------------------------------------------
-- Step 6: DELETE trigger — keep parity with the old secrets_ad.
-- ------------------------------------------------------------------

CREATE TRIGGER IF NOT EXISTS secrets_fts_ad AFTER DELETE ON secrets BEGIN
    INSERT INTO secrets_fts(secrets_fts, rowid, name, tags_text, description, category, namespace_label)
    VALUES (
        'delete',
        old.rowid,
        old.name,
        COALESCE(old.tags_text, ''),
        COALESCE(old.description, ''),
        old.category,
        COALESCE(old.namespace_label, (SELECT label FROM namespaces WHERE id = old.namespace_id))
    );
END;

-- ------------------------------------------------------------------
-- Step 7: rebuild the FTS5 index from all existing rows so that
-- secrets inserted before this migration are discoverable.
-- ------------------------------------------------------------------

INSERT INTO secrets_fts(secrets_fts) VALUES ('rebuild');
