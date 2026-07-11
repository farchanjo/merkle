-- Durable restore plans (Feature 002 / ADR-0034).
-- plan_id is independent of backup snapshot_id.
CREATE TABLE IF NOT EXISTS restore_plans (
    id BLOB PRIMARY KEY NOT NULL,
    source_backup_id BLOB NOT NULL,
    namespace_id BLOB NOT NULL,
    mode TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    validated_at TEXT NOT NULL,
    applied_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_restore_plans_namespace
    ON restore_plans (namespace_id);

CREATE INDEX IF NOT EXISTS idx_restore_plans_source_backup
    ON restore_plans (source_backup_id);
