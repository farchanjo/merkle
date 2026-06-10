-- Migration 003: compound index for the hot secret-list query.
--
-- `list_secrets` filters by namespace_id and orders by created_at ASC. Without
-- a compound index SQLite does a filtered scan followed by a separate sort
-- pass on every list. The (namespace_id, created_at) index turns that into a
-- single ordered range scan.
CREATE INDEX IF NOT EXISTS idx_secrets_namespace_created
    ON secrets(namespace_id, created_at);
