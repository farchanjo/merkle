---
status: accepted
date: 2026-05-22
deciders: [farchanjo]
consulted: []
informed: []
---

# 0013. FTS5 on Public Metadata Fields Only

## Context and Problem Statement

The LLM must be able to discover relevant Secrets by keyword: "find
all SSH keys tagged prod", "list database credentials for project
acme", "show me any token containing 'github'". Without full-text
search, the LLM must iterate all secrets in the namespace and filter
client-side, which is slow and context-expensive for large vaults.

SQLite's FTS5 module provides fast full-text search with ranking,
BM25 scoring, and porter stemming. However, FTS5 operates on
plaintext columns. Indexing the `private_blob` column would expose
secret material in the FTS5 index, which is stored as a separate
shadow table in the SQLite file.

The search index must be defined precisely: which columns are indexed,
which tokenizer is used, and what the update triggers look like to
keep the index in sync with the main table.

## Decision Drivers

* The FTS5 index must contain only public metadata: `name`,
  `category`, `tags`, `description`, `namespace_label`. The
  `private_blob` column is excluded categorically.
* Per-category public field selection: different categories have
  different public fields (e.g., `ssh` exposes `username`, `host`;
  `token` exposes `scope`, `endpoint`); the FTS5 content table
  must accommodate this.
* Tokenizer: `porter unicode61 remove_diacritics 2` provides English
  stemming and diacritic-normalized search, which is appropriate for
  developer tooling.
* Index synchronization: FTS5 shadow tables must be updated via
  SQLite triggers on `INSERT`, `UPDATE`, and `DELETE` of the main
  secrets table. Since the audit table is append-only, only the
  secrets table needs FTS5 maintenance.
* No private field leakage: the FTS5 index schema must be reviewed
  and validated to confirm no private columns are included.

## Considered Options

* Option A: FTS5 virtual table over public metadata columns only
* Option B: FTS5 over all columns (including private_blob)
* Option C: No full-text search; LLM filters via `vault.list`
  pagination
* Option D: External search index (Tantivy) over public metadata

## Decision Outcome

Chosen option: "Option A: FTS5 on public metadata fields only",
because FTS5 is already embedded in SQLite (no additional
dependency), provides the performance characteristics needed for
interactive LLM queries, and is trivially scoped to exclude private
columns by not including them in the virtual table definition.

The FTS5 virtual table is defined as a content table referencing the
main `secrets` table:

```sql
CREATE VIRTUAL TABLE secrets_fts USING fts5(
    name,
    category,
    tags,
    description,
    namespace_label,
    content='secrets',
    content_rowid='rowid',
    tokenize='porter unicode61 remove_diacritics 2'
);
```

Triggers keep the index in sync:

```sql
CREATE TRIGGER secrets_fts_insert AFTER INSERT ON secrets BEGIN
    INSERT INTO secrets_fts(rowid, name, category, tags,
        description, namespace_label)
    VALUES (new.rowid, new.name, new.category, new.tags,
        new.description, new.namespace_label);
END;
```

Update and delete triggers follow the same pattern. Per-category
extended public fields (e.g., `username`, `host` for `ssh`) are
concatenated into the `description` column at insert time by the
domain service rather than adding per-category FTS5 tables.

### Consequences

* Good, because FTS5 is bundled with SQLite; zero additional
  runtime dependency.
* Good, because the column whitelist in the virtual table definition
  is the authoritative guarantee that no private field is indexed;
  adding a new column to `secrets` does not automatically add it
  to the index.
* Good, because porter stemming enables natural-language queries:
  "authenticating" matches "authentication" in the index.
* Good, because BM25 scoring ranks results by relevance, improving
  LLM discovery for namespaces with hundreds of secrets.
* Bad, because the content table approach requires triggers to
  maintain sync; a trigger bug can cause stale or missing FTS5
  entries. Mitigated by a `doctor` check that validates FTS5
  consistency against the main table.
* Bad, because per-category extended public fields must be
  concatenated into the generic `description` column; structured
  search by exact field (e.g., `host = "bastion.prod"`) requires a
  separate SQL WHERE clause on the main table, not the FTS5 index.

## Pros and Cons of the Options

### Option A: FTS5 on public metadata only

* Good: fast; embedded; no extra dependency.
* Good: column whitelist is the security guarantee.
* Good: porter stemming and BM25 scoring for relevance.
* Bad: trigger maintenance required; doctor check needed.

### Option B: FTS5 over all columns

* Good: complete index; maximum recall.
* Bad: indexes `private_blob` plaintext into the FTS5 shadow table;
  any attacker who reads the SQLite file gets all secrets in
  plaintext via the index. This option is categorically rejected.

### Option C: No full-text search

* Good: simplest; no index maintenance.
* Bad: LLM must page through all secrets and filter client-side;
  for a namespace with 500+ secrets this is slow and
  context-window-expensive.
* Bad: the LLM cannot rank results by relevance; it gets all matching
  secrets with equal weight.

### Option D: Tantivy external index

* Good: more powerful search (faceting, custom analyzers).
* Bad: Tantivy is a separate embedded search engine; adds a
  significant dependency and a second data store that must be kept
  in sync.
* Bad: more complex failure modes: the main SQLite file and the
  Tantivy index can diverge on crash; recovery requires
  re-indexing.
* Bad: the performance gain over FTS5 is not justified for the
  expected vault sizes (< 10,000 secrets).

## Validation

* Privacy audit: introspect the `secrets_fts` shadow table; assert
  that no row contains any substring that appears in any
  `private_blob` column of the main `secrets` table.
* Stemming test: insert a secret with `description = "authentication
  token for production"`;  query FTS5 with `"authenticat*"`; assert
  match.
* Sync test: insert, update, and delete 1,000 secrets; run `doctor
  --check fts5`; assert zero inconsistencies.
* BM25 ranking test: insert 10 secrets; 3 with the keyword
  "github" in `name`, 7 with "github" in `description`; assert that
  name-match results rank higher.

## More Information

* SQLite FTS5 documentation: `https://sqlite.org/fts5.html`.
* FTS5 content tables:
  `https://sqlite.org/fts5.html#_content_and_content_rowid_options`.
* Related: [0003-sqlite-with-per-blob-encryption.md](0003-sqlite-with-per-blob-encryption.md)
* Related: [0012-eleven-built-in-categories-plus-cue-schema-for-custom.md](0012-eleven-built-in-categories-plus-cue-schema-for-custom.md)
* Superseded in part by: [0027-weighted-bm25-ranking-for-fts5-search.md](0027-weighted-bm25-ranking-for-fts5-search.md)
  — ADR-0027 corrects the implementation gap (wrong columns in migration 001,
  missing UPDATE trigger, no BM25 ordering) and specifies the authoritative
  per-column weight vector and query template. The tokenizer choice and
  privacy scope defined here remain unchanged.
