CREATE TABLE IF NOT EXISTS namespaces (
    id BLOB NOT NULL PRIMARY KEY,
    label TEXT NOT NULL UNIQUE,
    cwd_hash TEXT,
    policy_id BLOB,
    dek_version INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_namespaces_label ON namespaces(label);

CREATE TABLE IF NOT EXISTS secrets (
    id BLOB NOT NULL PRIMARY KEY,
    namespace_id BLOB NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    handle TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    public_metadata_json TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    current_version_id BLOB NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_secrets_namespace ON secrets(namespace_id);
CREATE INDEX IF NOT EXISTS idx_secrets_category ON secrets(category);

CREATE TABLE IF NOT EXISTS secret_versions (
    id BLOB NOT NULL PRIMARY KEY,
    secret_id BLOB NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version_no INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,
    aead_tag BLOB NOT NULL,
    associated_data BLOB NOT NULL,
    dek_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    deprecated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_versions_secret ON secret_versions(secret_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_versions_secret_version ON secret_versions(secret_id, version_no);

CREATE TABLE IF NOT EXISTS audit_entries (
    id BLOB NOT NULL PRIMARY KEY,
    seq INTEGER NOT NULL UNIQUE,
    ts TEXT NOT NULL,
    namespace_id BLOB NOT NULL,
    caller_program TEXT,
    op TEXT NOT NULL,
    outcome TEXT NOT NULL,
    denial_reason TEXT,
    handle TEXT,
    sensitivity TEXT,
    prev_hash TEXT,
    current_hash TEXT NOT NULL UNIQUE,
    hmac TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_entries(seq);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_entries(ts);
CREATE INDEX IF NOT EXISTS idx_audit_op ON audit_entries(op);

CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_entries
BEGIN
    SELECT RAISE(ABORT, 'audit_entries is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_entries
BEGIN
    SELECT RAISE(ABORT, 'audit_entries is append-only: DELETE is forbidden');
END;

CREATE TABLE IF NOT EXISTS pinned_head (
    singleton INTEGER PRIMARY KEY DEFAULT 1 CHECK(singleton = 1),
    head_hash TEXT NOT NULL,
    head_seq INTEGER NOT NULL,
    head_id BLOB NOT NULL,
    updated_at TEXT NOT NULL,
    -- Head-commitment MAC over head_hash || head_seq || head_id || entry_count.
    -- Nullable: recovery/legacy heads may lack it, and the chain verifier fails
    -- closed (HeadMacMismatch) on a NULL tag during a keyed pass.
    hmac_head TEXT
);

CREATE TABLE IF NOT EXISTS backups (
    id BLOB NOT NULL PRIMARY KEY,
    namespace_id BLOB NOT NULL REFERENCES namespaces(id),
    snapshot_id BLOB NOT NULL,
    trigger TEXT NOT NULL,
    recipients_json TEXT NOT NULL,
    artifact_json TEXT NOT NULL,
    hmac TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    secret_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_backups_namespace ON backups(namespace_id);

CREATE TABLE IF NOT EXISTS namespace_policies (
    id BLOB NOT NULL PRIMARY KEY,
    namespace_id BLOB NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    policy_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_namespace ON namespace_policies(namespace_id);

CREATE TABLE IF NOT EXISTS companion_devices (
    device_id BLOB NOT NULL PRIMARY KEY,
    ed25519_pubkey BLOB NOT NULL,
    x25519_pubkey BLOB NOT NULL,
    class TEXT NOT NULL,
    attestation_chain BLOB NOT NULL,
    enrolled_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE VIRTUAL TABLE IF NOT EXISTS secrets_fts USING fts5(
    handle,
    description,
    fts_keywords,
    content='secrets',
    content_rowid='rowid',
    tokenize='porter unicode61 remove_diacritics 2'
);

CREATE TRIGGER IF NOT EXISTS secrets_ai AFTER INSERT ON secrets BEGIN
    INSERT INTO secrets_fts(rowid, handle, description, fts_keywords)
    VALUES (
        new.rowid,
        new.handle,
        COALESCE(json_extract(new.public_metadata_json, '$.description'), ''),
        COALESCE(json_extract(new.public_metadata_json, '$.fts_keywords'), '')
    );
END;

CREATE TRIGGER IF NOT EXISTS secrets_ad AFTER DELETE ON secrets BEGIN
    INSERT INTO secrets_fts(secrets_fts, rowid, handle, description, fts_keywords)
    VALUES (
        'delete',
        old.rowid,
        old.handle,
        COALESCE(json_extract(old.public_metadata_json, '$.description'), ''),
        COALESCE(json_extract(old.public_metadata_json, '$.fts_keywords'), '')
    );
END;
