//! Schema constants — the embedded migration SQL.
//!
//! Constants are kept here for reference / doc purposes only.
//! The actual migrations are applied via `sqlx::migrate!()`.

/// The initial DDL for the merkle-adapter-sqlite database.
///
/// Tables: `namespaces`, `secrets`, `secret_versions`, `audit_entries`,
/// `pinned_head`, `backups`, `namespace_policies`, `companion_devices`.
/// Virtual table: `secrets_fts` (FTS5, porter unicode61 tokenizer).
///
/// WAL mode and foreign keys are set via `PRAGMA` at migration time.
pub const INITIAL_SCHEMA: &str = include_str!("migrations/001_initial.sql");

/// Migration 002: weighted BM25 FTS5 schema + UPDATE trigger (ADR-0027).
///
/// - Drops the old `secrets_fts` virtual table (wrong columns from migration 001).
/// - Adds `name`, `tags_text`, and `namespace_label` columns to `secrets`.
/// - Recreates `secrets_fts` with column order `(name, tags, description,
///   category, namespace_label)` matching the BM25 weight vector (10,5,3,2,1).
/// - Adds INSERT, UPDATE (new), and DELETE triggers.
/// - Rebuilds the index from all existing rows.
pub const FTS5_BM25_MIGRATION: &str = include_str!("migrations/002_fts5_bm25.sql");
