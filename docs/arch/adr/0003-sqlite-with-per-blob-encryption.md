---
status: accepted
date: 2026-05-22
deciders: [farchanjo]
consulted: []
informed: []
---

# 0003. SQLite with Per-Blob Encryption

## Context and Problem Statement

Merkle needs a persistence backend that stores Secrets, their
versioned history, the audit Hash Chain, Namespace metadata, and
policy configuration. The backend must support full-text search on
public metadata fields, provide append-only guarantees for the audit
log, allow concurrent reads from multiple MCP Adapter processes, and
integrate with the broader Rust ecosystem without requiring a forked
or non-upstream dependency.

Two concerns pull in different directions: the private_blob column
must never be readable without the Namespace DEK, but public metadata
columns (name, category, tags, description) must be plaintext so that
FTS5 can index them and the LLM can reason about Secrets without
decrypting anything. This means encryption must be selective rather
than file-wide.

## Decision Drivers

* No forked or patched dependencies: the storage backend must be
  available as a standard Rust crate (`rusqlite`) without requiring
  a commercial or externally-maintained SQLite fork.
* Public metadata must be plaintext for FTS5 indexing; FTS5 cannot
  operate on encrypted columns.
* Private material (the `private_blob` column) must be encrypted at
  rest with a per-secret nonce; compromise of one blob must not
  compromise others.
* SQLite WAL mode supports concurrent readers with a single writer,
  matching the agent-plus-adapter topology from
  [0002-adopt-agent-plus-mcp-adapter-topology.md](0002-adopt-agent-plus-mcp-adapter-topology.md).
* Append-only audit log enforcement via SQLite triggers (no UPDATE or
  DELETE on the audit table).
* Local-first: no network dependency, no server process to manage.

## Considered Options

* Option A: SQLite (rusqlite) with per-blob XChaCha20-Poly1305
  encryption
* Option B: SQLCipher (full-file encryption)
* Option C: Filesystem-level encryption (LUKS, FileVault, BitLocker)
  with plain SQLite
* Option D: Sled (embedded Rust key-value store) with per-value
  encryption

## Decision Outcome

Chosen option: "Option A: SQLite with per-blob encryption", because
it avoids the SQLCipher fork dependency, preserves plaintext public
metadata for FTS5, and keeps the private_blob encrypted with
per-secret nonces under the Namespace DEK. The per-blob approach
means that even if the database file is copied, each blob requires
its own nonce + DEK to decrypt.

### Consequences

* Good, because `rusqlite` is the standard SQLite binding for Rust;
  no fork, no license complexity, no build-time C compilation beyond
  the bundled SQLite amalgamation.
* Good, because FTS5 operates on plaintext public metadata columns
  without any special handling; search is as fast as native SQLite
  FTS5.
* Good, because per-blob encryption with unique nonces means that a
  database dump does not reveal plaintext even if the attacker has
  the file; they would also need the Namespace DEK.
* Good, because WAL mode allows multiple MCP Adapter processes to
  read simultaneously while the Vault Agent holds the single write
  lock.
* Good, because SQLite triggers on the audit table enforce
  append-only discipline at the storage layer.
* Bad, because per-blob encryption means the application layer (not
  the storage layer) is responsible for encrypt-on-write and
  decrypt-on-read for every private_blob access; this is a
  correctness surface that must be tested carefully.
* Bad, because SQLite does not natively enforce the `private_blob`
  column is always encrypted; the application must never insert
  plaintext into that column. Addressed by the CUE schema and
  domain service type system.

## Pros and Cons of the Options

### Option A: SQLite with per-blob XChaCha20-Poly1305

* Good: standard upstream SQLite; no fork.
* Good: FTS5 works natively on plaintext columns.
* Good: per-blob nonces; compromise is scoped to one secret.
* Good: WAL mode; concurrent reads.
* Bad: application-layer encryption responsibility.

### Option B: SQLCipher

* Good: entire database file is opaque to an attacker with the file.
* Bad: SQLCipher is a fork of SQLite maintained by Zetetic; it
  diverges from upstream SQLite periodically and has different
  licensing (BSL / commercial for some integrations).
* Bad: FTS5 requires the entire database to be decrypted in memory
  to run queries; full-file encryption and column-level plaintext
  are mutually exclusive.
* Bad: no standard Rust crate; requires building the SQLCipher
  amalgamation via `libsqlcipher-sys`, which is community-maintained.

### Option C: Filesystem-level encryption

* Good: transparent to the application; no code changes.
* Bad: relies entirely on the OS being configured correctly; not
  portable across macOS (FileVault), Linux (LUKS), and Windows
  (BitLocker) without operator action.
* Bad: provides no protection against a running process that reads
  the database file while the filesystem is mounted (the common
  threat model for a compromised desktop).
* Bad: FTS5 works, but so does an attacker who obtains the mounted
  filesystem while the user is logged in.

### Option D: Sled embedded key-value store

* Good: pure Rust; no C amalgamation.
* Bad: Sled lacks FTS5; full-text search would require an external
  index (Tantivy), adding significant complexity.
* Bad: Sled's transactional model is less mature than SQLite for
  append-only audit logs with trigger enforcement.
* Bad: migration from Sled to another store is harder than SQLite
  (standard SQL dump/restore).

## Validation

* Unit tests confirm that any row inserted into the `secrets` table
  with a non-encrypted `private_blob` fails at the domain service
  layer before reaching the storage adapter.
* FTS5 smoke test: insert 1,000 secrets with varied public metadata;
  confirm full-text queries return correct results and never surface
  private_blob content.
* Audit trigger test: attempt an UPDATE or DELETE on the audit table
  via raw SQL; confirm the trigger rolls back the transaction.
* WAL concurrency test: two readers and one writer; confirm zero
  `SQLITE_BUSY` errors at 100 ops/s.

## More Information

* SQLite WAL mode documentation: `https://sqlite.org/wal.html`.
* FTS5 tokenizer documentation: `https://sqlite.org/fts5.html`.
* `rusqlite` crate: `https://crates.io/crates/rusqlite`.
* Related: [0004-xchacha20-poly1305-aead-for-blobs.md](0004-xchacha20-poly1305-aead-for-blobs.md)
* Related: [0013-fts5-on-public-metadata-fields-only.md](0013-fts5-on-public-metadata-fields-only.md)
* Related: [0009-merkle-style-audit-hash-chain.md](0009-merkle-style-audit-hash-chain.md)

## Amendment — 2026-05-22

### VaultRootKey Rotation Atomicity (mandatory)

VaultRootKey rotation MUST execute inside a single SQLite transaction that
simultaneously writes the new wrapped VaultRootKey row AND replaces every
wrapped NamespaceDek row in the `namespace_deks` table. Both operations must
be committed together or not at all.

If the transaction fails at any point — power loss, OOM, SIGKILL, or any
other hard abort — the database remains atomically pre-rotation: all
NamespaceDek rows are still wrapped under the old VaultRootKey, and the old
VaultRootKey row is still the active row in `vault_root_keys`. No partial
re-wrap is possible because SQLite WAL rolls back uncommitted transactions on
recovery.

**Recovery procedure for mid-rotation detection.** On agent startup, the boot
sequence MUST perform the following check before entering Unsealed State:

1. Query `vault_root_keys` for a row with `pending_rotation = true`.
2. If such a row is present but no corresponding new VaultRootKey row has been
   committed (i.e., the row count in `vault_root_keys` has not increased above
   the last known count stored in `config.toml`), the agent detects a
   half-committed rotation.
3. In that case, the agent MUST use the SQLite WAL to roll back any
   half-committed NamespaceDek wraps, clear the `pending_rotation` flag, and
   emit a `vrk_rotation_rollback` audit entry before proceeding. The vault
   remains fully operational under the pre-rotation VaultRootKey.
4. If no `pending_rotation` flag is set, boot continues normally.

The rationale: because re-wrapping NamespaceDek rows is proportional to the
number of Namespaces, a partial write without this guard would leave some DEKs
wrapped under the new VaultRootKey and others under the old one, making the
vault unrecoverable without a backup.

Cross-reference: [0015-rust-keyring-crate-for-multi-os-keychain.md](0015-rust-keyring-crate-for-multi-os-keychain.md)
for Keychain interaction during VaultRootKey rotation (new Master Key written
to Keychain must also be atomic with the database transaction where feasible,
or performed after successful commit with the pre-rotation key still valid as
a fallback).
