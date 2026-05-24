//! Schema constants — the embedded initial migration SQL.
//!
//! `INITIAL_SCHEMA` is kept here as a `&str` constant for reference / doc
//! purposes. The actual migration is applied via `sqlx::migrate!()`.

/// The initial DDL for the merkle-adapter-sqlite database.
///
/// Tables: `namespaces`, `secrets`, `secret_versions`, `audit_entries`,
/// `pinned_head`, `backups`, `namespace_policies`, `companion_devices`.
/// Virtual table: `secrets_fts` (FTS5, porter unicode61 tokenizer).
///
/// WAL mode and foreign keys are set via `PRAGMA` at migration time.
pub const INITIAL_SCHEMA: &str = include_str!("migrations/001_initial.sql");
