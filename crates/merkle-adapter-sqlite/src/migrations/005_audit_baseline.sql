-- 005: trusted audit baseline (checkpoint) for key-provenance recovery (ADR-0029).
--
-- A single-row table (mirrors pinned_head) holding an operator-pinned trust
-- anchor. When a baseline is present the chain verifier authenticates it under
-- the current audit HMAC key (hmac = HMAC(key, DOMAIN || baseline_hash ||
-- baseline_seq || baseline_id || entry_count)) and requires per-entry HMAC
-- authenticity only from baseline_seq forward; the quarantined prefix is still
-- structurally (hash-chain) verified across the whole log.
--
-- Authored as a forward migration (rather than editing 001_initial.sql in place)
-- so existing vault databases keep their applied-migration checksums. Fresh
-- installs converge here via 001 -> 005. The `hmac` column is nullable only for
-- records built before a key is attached; the verifier fails closed on a NULL
-- tag (ChainOutcome::BaselineMacMismatch).

CREATE TABLE IF NOT EXISTS audit_baseline (
    singleton INTEGER PRIMARY KEY DEFAULT 1 CHECK(singleton = 1),
    baseline_seq INTEGER NOT NULL,
    baseline_id BLOB NOT NULL,
    baseline_hash TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    hmac TEXT
);
