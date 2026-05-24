---
status: accepted
date: 2026-05-24
deciders: [farchanjo]
consulted: []
informed: []
---

# 0027. Weighted BM25 Ranking for FTS5 Search

## Context and Problem Statement

ADR-0013 decided that the FTS5 virtual table `secrets_fts` would be
built over the public metadata fields of the `secrets` table, with BM25
scoring providing relevance-ordered results for LLM-driven secret
discovery.

The implementation diverges from that decision in two interconnected ways.

**Schema gap — wrong columns indexed.** ADR-0013 §Decision Outcome
specifies the virtual table must contain `name`, `category`, `tags`,
`description`, and `namespace_label`. The live migration at
`crates/merkle-adapter-sqlite/src/migrations/001_initial.sql:111–118`
instead defines:

```sql
CREATE VIRTUAL TABLE IF NOT EXISTS secrets_fts USING fts5(
    handle,
    description,
    fts_keywords,
    ...
);
```

`name` is absent. `category`, `tags`, and `namespace_label` are absent.
`handle` is a compound URI (`vault://namespace/category/name`) whose
slash-separated tokens are not independently searchable stems. A query
for `"github"` against a secret named `github-deploy-key` will not match
on `name` because `name` is not in the index. `fts_keywords` is a
synthetic blob that has no corresponding column in the `secrets` table;
it is populated from `json_extract(public_metadata_json, '$.fts_keywords')`
which is always empty because no path in the write stack populates that
field.

**Ranking gap — no BM25 ordering.** The `list_secrets` query in
`crates/merkle-adapter-sqlite/src/secrets.rs:218–221` orders results by
`s.created_at ASC` regardless of whether an `fts_query` filter is active.
The FTS5 `bm25()` function is never called; results are not sorted by
relevance. A query such as `"OOB ssh key ed25519 latitude"` returns
matching secrets in insertion order, not ranked by how closely the public
metadata matches the query terms.

**Update-trigger gap.** The migration defines an INSERT trigger
(`secrets_ai`) and a DELETE trigger (`secrets_ad`) but no UPDATE trigger.
When a secret's `public_metadata_json` is mutated (e.g., after `rotate`
updates the description), the FTS5 index retains the stale pre-rotation
text. This violates the strong-consistency guarantee stated in ADR-0013
§Decision Drivers ("triggers keep the index in sync").

**MCP surface gap.** `vault.search` in
`crates/merkle-adapter-mcp/src/tools/secrets.rs:466–477` returns only
`handle`, `name`, `category`, and `sensitivity` per result. It exposes no
relevance score, no BM25 rank position, and no highlight snippets, so the
LLM cannot reason about which result is more relevant or why.

These gaps together produce Elasticsearch-class query quality that is
worse than a naive LIKE scan: results are returned in insertion order,
the most discriminating metadata column (`name`) is not indexed, and the
caller receives no signal to distinguish a precise name match from a
marginal description substring match.

## Decision Drivers

* **Per-column weight vector**: the `bm25()` auxiliary function in FTS5
  accepts per-column weight arguments. A higher weight on `name` and `tags`
  than on `description`, and a lower weight on `namespace_label`, reflects
  the actual discriminating power of each field for secret discovery.
  Default SQLite `bm25()` (all columns weighted 1.0) would rank a
  description match equally with a name match, which misrepresents intent.
* **BM25 parameters (k1, b)**: SQLite FTS5 hard-codes `k1 = 1.2` and
  `b = 0.75` internally; these parameters are not tunable via the SQL
  interface. The operator-facing weight vector (via `bm25()` column
  arguments) is the only lever available without patching SQLite. This
  ADR does not attempt to tune `k1` or `b` beyond the SQLite defaults.
* **Score exposure in response**: the LLM must receive a numeric score per
  result so it can decide whether the top result is a confident match or a
  weak partial match. Returning rank position alone is insufficient for
  queries where the score gap between rank-1 and rank-2 is large.
* **Highlight snippets**: the FTS5 `highlight()` and `snippet()` auxiliary
  functions produce caller-ready HTML-stripped text with matched terms
  marked. Returning a snippet per result allows the LLM to confirm relevance
  without reading full descriptions.
* **Tokenizer reaffirmation**: ADR-0013 chose `porter unicode61 remove_diacritics 2`.
  This decision is not re-opened. Porter stemming enables natural-language
  queries ("authenticating" matches "authentication"); `remove_diacritics 2`
  normalizes UTF-8 diacritics at index time and query time.
* **Pagination interaction with ranking**: ranked results must preserve
  rank order across pages. A cursor based on `(score, rowid)` is required
  because score is not a stable column in the secrets table. The response
  must expose `offset` as the pagination mechanism for ranked queries (not
  an opaque cursor based on `created_at`), since rank position is relative
  to the full result set.
* **Privacy invariant (ADR-0013)**: the column whitelist in the virtual
  table is the authoritative security guarantee that no private field is
  indexed. Every column added to `secrets_fts` must appear in the approved
  public metadata list: `name`, `category`, `tags`, `description`,
  `namespace_label`. The `private_blob` column, `ciphertext`, `nonce`,
  `aead_tag`, and all fields under `secret_versions` are categorically
  excluded.
* **Zero new runtime dependency**: BM25 and the `highlight()`/`snippet()`
  auxiliary functions are bundled with SQLite's FTS5 module. No additional
  crate is required.

## Considered Options

* **Option A**: FTS5 default `bm25()` per ADR-0013 (columns: as specified
  in ADR-0013; weight: uniform 1.0; score: not exposed; ranking: ORDER BY
  bm25 ascending).
* **Option B**: FTS5 weighted `bm25()` with per-column weights tuned for
  secret discovery; correct column set; score and highlights exposed in
  response; ranked ORDER BY; pagination via offset. (Selected)
* **Option C**: FTS5 + post-rank rerank in the application layer using
  TF-IDF heuristics on category proximity. Domain service consumes the
  unweighted BM25 results, then re-ranks by computing a category affinity
  score (e.g., if the query contains "ssh", boost `category = "ssh"`
  results).
* **Option D**: Tantivy migration — replace FTS5 with an embedded Tantivy
  index. Explicitly rejected in ADR-0013 Option D, which catalogues the
  reasons: additional dependency, second data store requiring sync, higher
  failure complexity, performance gain not justified for expected vault
  sizes (< 10,000 secrets). This option is re-rejected without further
  analysis.

## Decision Outcome

Chosen option: **Option B — FTS5 weighted `bm25()` with per-column
weights**, because:

1. It fixes all three gaps (schema, ranking, update trigger) within the
   FTS5 + SQLite constraint established by ADR-0013.
2. The weight vector is the minimal lever available in SQLite FTS5 to
   encode domain knowledge about field discriminating power.
3. Score and highlight exposure are zero-cost additions using FTS5
   auxiliary functions; they require no extra queries.
4. Option A (uniform weight) is rejected because it ranks description
   matches equally with name matches. A secret whose `name` contains the
   exact query term is unambiguously more relevant than one whose
   `description` contains a stemmed variant.
5. Option C (application-layer rerank) is rejected because it introduces
   domain logic in the storage adapter query path, violating the hexagonal
   architecture principle that ranking is a persistence concern. It also
   requires a second pass over the result set, adding latency proportional
   to result count.

### Per-Column Weight Vector

| Column | Weight | Rationale |
|---|---|---|
| `name` | 10.0 | Secret name is the most discriminating field; an exact name match is almost always the correct result. |
| `tags` | 5.0 | Tags encode structured classification (`env:prod`, `role:bastion`); a tag match is highly intentional. |
| `description` | 3.0 | Description is free-form; matches are relevant but less precise than name or tag matches. |
| `category` | 2.0 | Category is a short closed-enum token; matching it provides moderate signal, especially for category-specific queries. |
| `namespace_label` | 1.0 | Namespace label is usually the same for all secrets in a session; matching it provides minimal discriminating signal. |

The `bm25()` call template is:

```sql
bm25(secrets_fts, 10.0, 5.0, 3.0, 2.0, 1.0)
```

Column argument positions map to the `CREATE VIRTUAL TABLE` column
declaration order: `name` (pos 0, weight 10.0), `tags` (pos 1,
weight 5.0), `description` (pos 2, weight 3.0), `category` (pos 3,
weight 2.0), `namespace_label` (pos 4, weight 1.0). The order in the
`CREATE VIRTUAL TABLE` statement is authoritative; any deviation invalidates
the weight mapping.

### Response Contract

Each item in a ranked search response carries:

| Field | Type | Description |
|---|---|---|
| `score` | `f64` | Raw BM25 score from `bm25(secrets_fts, ...)`. Negative in SQLite (more negative = better match). Exposed as-is; callers MUST NOT assume a specific range. |
| `bm25_rank` | `u32` | 1-based position in the ranked result set for this page + offset. `bm25_rank = 1` is the best match. |
| `highlights` | `array` | Per-field highlight snippets from `highlight()` or `snippet()`. See `SearchHighlight` schema below. |

`SearchHighlight` per-field structure:

| Field | Type | Description |
|---|---|---|
| `field` | `string` | The FTS5 column name that produced this highlight (`name`, `tags`, `description`, `category`, `namespace_label`). |
| `snippet` | `string` | Extracted text with matched terms wrapped in `<b>` tags (FTS5 `highlight()` output). Maximum 64 tokens from `snippet()`. |

### Pagination for Ranked Queries

When `fts_query` is present, pagination uses `limit` and `offset`
(not the opaque `next_cursor` from the created-at ordering). The response
includes `total` (count of all matches) and `has_more` (boolean).
Callers advance pages by incrementing `offset` by `limit`.

Non-ranked queries (no `fts_query`) retain the existing `next_cursor`
opaque pagination.

### Consequences

* Good, because `name` is now indexed and weighted highest; a query like
  `"github"` against a secret named `github-deploy-key` will now rank that
  secret at position 1 ahead of secrets that merely mention "github" in a
  description.
* Good, because the UPDATE trigger gap is closed; post-rotate description
  updates are reflected in the FTS5 index within the same transaction.
* Good, because `score` and `highlights` let the LLM evaluate confidence
  without additional round-trips.
* Good, because the `doctor` check gains a new sub-check (`fts5_schema`)
  that validates the virtual table column list against this ADR's
  authoritative spec, catching future drift early.
* Bad, because the `secrets_fts` virtual table must be dropped and
  recreated in a migration (migration `002`); existing FTS5 index data
  for already-created secrets is invalidated. A rebuild trigger or
  `INSERT INTO secrets_fts(secrets_fts) VALUES ('rebuild')` is required
  after migration.
* Bad, because adding `snippet()` / `highlight()` per-field increases
  the per-row computation cost of search queries. For namespaces with
  10,000+ secrets and complex queries this may add 5–20 ms. Mitigated by
  capping `highlights` at the top 5 matched fields per result and using
  `snippet()` (bounded window) rather than `highlight()` (full-field scan)
  for long descriptions.
* Bad, because `bm25_rank` is 1-based within the current page; callers
  must add `offset` to compute the global rank. Callers MUST NOT treat
  `bm25_rank` as a global rank without adjusting for the page offset.

## Index Schema

This section is the authoritative specification the implementation follows.
Any deviation between the live migration SQL and this section constitutes
a spec-to-code gap that must be resolved by updating the code.

### Virtual Table (migration 002)

```sql
CREATE VIRTUAL TABLE IF NOT EXISTS secrets_fts USING fts5(
    name,
    tags,
    description,
    category,
    namespace_label,
    content='secrets',
    content_rowid='rowid',
    tokenize='porter unicode61 remove_diacritics 2'
);
```

The `content='secrets'` directive makes `secrets_fts` a content table;
the FTS5 index stores tokens only, not the original text. The original
text for `highlight()` and `snippet()` is read from the `secrets` table
at query time. This means:

- `name`, `category` are direct columns of the `secrets` table.
- `tags` must be materialized as a space-separated tag string (e.g.,
  `"env:prod role:bastion"`) at index time by the triggers; it is not a
  column of the `secrets` table (which stores `tags_json`).
- `description` is extracted from `json_extract(public_metadata_json, '$.description')`.
- `namespace_label` requires a join to `namespaces` at index time (via
  trigger) and is stored as a denormalized column in `secrets` as
  `namespace_label TEXT` added by migration 002, OR materialized inline
  in the trigger body via a subquery.

Implementation note: to avoid altering the `secrets` table (which would
require a separate migration for every row), the triggers materialize
`tags` and `namespace_label` inline using subqueries. The FTS5 content
table stores only the indexed tokens, not the original content; the
content table backing (`content='secrets'`) causes FTS5 to look up the
`name` and `category` columns directly from `secrets` at snippet
generation time. `tags` and `namespace_label` are stored as auxiliary
columns in the FTS5 index itself (not backed by the content table's
columns) by declaring them in the virtual table definition without a
`content=` mapping. This is the standard FTS5 mixed-content pattern.

Because SQLite FTS5 with `content=` only back-reads columns that exist in
the named content table, the recommended implementation for migration 002
is to add two generated columns to the `secrets` table:

```sql
-- migration 002: add generated columns for FTS5 content table backing
ALTER TABLE secrets ADD COLUMN tags_text TEXT
    GENERATED ALWAYS AS (
        -- Flatten tags_json [{key,value},...] to "key:value key:value" space-separated
        -- SQLite does not have a native JSON array map function; this is handled by
        -- an application-layer migration script that rewrites existing rows, or by
        -- the insert/update triggers populating a real (non-generated) column.
        NULL
    ) STORED;

ALTER TABLE secrets ADD COLUMN namespace_label TEXT;
```

The `namespace_label` column is populated by the INSERT trigger via a
correlated subquery against the `namespaces` table. This is a one-time
denormalization; namespace labels are immutable after creation (ADR-0008).

The `tags_text` column is populated by the INSERT and UPDATE triggers as a
space-separated `key:value` string derived from `tags_json`.

### Triggers (migration 002)

All three triggers (INSERT, UPDATE, DELETE) are required. The UPDATE
trigger is new; it was absent from migration 001.

```sql
-- INSERT trigger
CREATE TRIGGER IF NOT EXISTS secrets_fts_ai AFTER INSERT ON secrets BEGIN
    UPDATE secrets
    SET
        namespace_label = (
            SELECT label FROM namespaces WHERE id = new.namespace_id
        ),
        tags_text = (
            -- Application layer responsible for populating this on write;
            -- trigger reads the value after the application layer sets it.
            -- See note below.
            new.tags_text
        )
    WHERE id = new.id;
    INSERT INTO secrets_fts(rowid, name, tags, description, category, namespace_label)
    VALUES (
        new.rowid,
        new.handle,  -- note: name is embedded in handle; see note below
        COALESCE(new.tags_text, ''),
        COALESCE(json_extract(new.public_metadata_json, '$.description'), ''),
        new.category,
        (SELECT label FROM namespaces WHERE id = new.namespace_id)
    );
END;

-- UPDATE trigger (new — fixes the missing-trigger gap)
CREATE TRIGGER IF NOT EXISTS secrets_fts_au AFTER UPDATE ON secrets BEGIN
    INSERT INTO secrets_fts(secrets_fts, rowid, name, tags, description, category, namespace_label)
    VALUES (
        'delete',
        old.rowid,
        old.handle,
        COALESCE(old.tags_text, ''),
        COALESCE(json_extract(old.public_metadata_json, '$.description'), ''),
        old.category,
        (SELECT label FROM namespaces WHERE id = old.namespace_id)
    );
    INSERT INTO secrets_fts(rowid, name, tags, description, category, namespace_label)
    VALUES (
        new.rowid,
        new.handle,
        COALESCE(new.tags_text, ''),
        COALESCE(json_extract(new.public_metadata_json, '$.description'), ''),
        new.category,
        (SELECT label FROM namespaces WHERE id = new.namespace_id)
    );
END;

-- DELETE trigger
CREATE TRIGGER IF NOT EXISTS secrets_fts_ad AFTER DELETE ON secrets BEGIN
    INSERT INTO secrets_fts(secrets_fts, rowid, name, tags, description, category, namespace_label)
    VALUES (
        'delete',
        old.rowid,
        old.handle,
        COALESCE(old.tags_text, ''),
        COALESCE(json_extract(old.public_metadata_json, '$.description'), ''),
        old.category,
        (SELECT label FROM namespaces WHERE id = old.namespace_id)
    );
END;
```

**Note on `name` vs `handle`**: the `secrets` table does not have a
standalone `name` column; the secret's name is the final path segment of
the `handle` URI (`vault://label/category/name`). The implementation MUST
extract the name segment from the handle before inserting into
`secrets_fts`. The triggers above use `new.handle` as a placeholder;
the actual implementation should use
`SUBSTR(new.handle, INSTR(new.handle, '/', INSTR(new.handle, '/', INSTR(new.handle, '/') + 1) + 1) + 1)`
or, preferably, have the application layer write a `name` column to the
`secrets` table in migration 002.

The recommended resolution for the implementation phase is to add a real
`name TEXT` column to the `secrets` table in migration 002, populated by
the application layer at write time, so that the trigger body can use
`new.name` directly.

### Ranked Query Template

```sql
SELECT
    s.id, s.namespace_id, s.handle, s.category, s.sensitivity,
    s.public_metadata_json, s.tags_json, s.current_version_id, s.created_at,
    bm25(secrets_fts, 10.0, 5.0, 3.0, 2.0, 1.0)      AS bm25_score,
    highlight(secrets_fts, 0, '<b>', '</b>')            AS hl_name,
    highlight(secrets_fts, 1, '<b>', '</b>')            AS hl_tags,
    snippet(secrets_fts, 2, '<b>', '</b>', '...', 20)  AS hl_description,
    highlight(secrets_fts, 3, '<b>', '</b>')            AS hl_category,
    highlight(secrets_fts, 4, '<b>', '</b>')            AS hl_namespace_label
FROM secrets s
JOIN secrets_fts f ON f.rowid = s.rowid
WHERE
    s.namespace_id = ?1
    AND secrets_fts MATCH ?2
ORDER BY bm25_score ASC    -- FTS5 bm25() returns negative; ASC = best first
LIMIT ?3
OFFSET ?4;
```

The weight argument order in `bm25(secrets_fts, w0, w1, w2, w3, w4)`
maps positionally to the column declaration order in
`CREATE VIRTUAL TABLE secrets_fts`: `name` (w0=10.0), `tags` (w1=5.0),
`description` (w2=3.0), `category` (w3=2.0), `namespace_label` (w4=1.0).

## Validation

All TDD artifacts are authored before any source-code edit (impl-guard
requirement per ADR-0025 pattern). Each test below is a failing test that
must be committed before the fix.

1. **Privacy audit** — `crates/merkle-adapter-sqlite/tests/storage_integration.rs`:
   Introspect `secrets_fts` shadow tables after inserting secrets; assert
   no substring present in any `private_blob` (ciphertext bytes) appears
   in any FTS5 index row. Assert `secrets_fts` virtual table column list
   is exactly `{name, tags, description, category, namespace_label}` by
   querying `PRAGMA table_info(secrets_fts)`.

2. **BM25 ranking test** — `crates/merkle-adapter-sqlite/tests/storage_integration.rs`:
   Insert 10 secrets: 3 with the keyword `"github"` in `name`, 7 with
   `"github"` only in `description`. Execute the ranked query with
   `fts_query = "github"`. Assert all 3 name-match results appear in
   positions 1–3 (i.e., their `bm25_rank` values are less than the
   `bm25_rank` values of the description-match results).

3. **Highlight test** — `crates/merkle-adapter-sqlite/tests/storage_integration.rs`:
   Insert a secret with `name = "bastion-prod-key"`,
   `description = "SSH key for the production bastion host"`. Execute
   ranked query with `fts_query = "bastion"`. Assert the response for
   that secret contains at least one `highlights` entry with `field = "name"`
   and `snippet` containing `"<b>bastion</b>"`. Assert the `description`
   highlight entry snippet contains `"<b>bastion</b>"` surrounded by
   context tokens.

4. **Update trigger test** — `crates/merkle-adapter-sqlite/tests/storage_integration.rs`:
   Insert a secret with `description = "old description"`. Perform an
   update that sets `description = "new production database credential"`.
   Execute ranked query with `fts_query = "production"`. Assert the updated
   secret appears in results. Execute ranked query with `fts_query = "old"`.
   Assert the updated secret does NOT appear in results (stale index entry
   removed).

5. **Weighted ordering test** — `crates/merkle-adapter-sqlite/tests/storage_integration.rs`:
   Insert secret A with `name = "deploy-token"` (token not in description).
   Insert secret B with `name = "unrelated"` and `description` containing
   50 occurrences of the word "deploy". Execute ranked query with
   `fts_query = "deploy"`. Assert secret A (`bm25_rank = 1`) ranks above
   secret B because the name weight (10.0) dominates the description TF
   inflation.

6. **Pagination preserves rank** — `crates/merkle-adapter-sqlite/tests/storage_integration.rs`:
   Insert 15 secrets all matching `fts_query = "acme"` with varying
   `name` and `description` match strength. Fetch page 1 (`limit=5`,
   `offset=0`) and page 2 (`limit=5`, `offset=5`). Assert `bm25_score` of
   the last result on page 1 is less relevant (higher absolute value) than
   the first result on page 2. Assert no handle appears in both pages.

7. **Doctor FTS5 schema check** — `crates/merkle-adapter-sqlite/tests/storage_integration.rs`:
   Call `doctor --check fts5_schema`; assert the check passes. Drop and
   recreate `secrets_fts` with incorrect columns; call
   `doctor --check fts5_schema`; assert the check fails with a
   `Fts5SchemaMismatch` error.

8. **Private fields never appear in highlights** — `crates/merkle-adapter-sqlite/tests/storage_integration.rs`:
   Insert a secret. Execute ranked query. For every `highlights` entry in
   every result, assert none of the field names is `private_blob`,
   `ciphertext`, `nonce`, `aead_tag`, or `associated_data`. Assert the
   snippet text does not contain the literal ciphertext bytes of any secret.

## More Information

* [ADR-0013](0013-fts5-on-public-metadata-fields-only.md) — original FTS5
  decision; this ADR extends it. ADR-0013 remains the authority on
  tokenizer choice (`porter unicode61 remove_diacritics 2`), privacy scope
  (public metadata only), and the content table pattern.
* [ADR-0003](0003-sqlite-with-per-blob-encryption.md) — SQLite WAL mode,
  per-blob XChaCha20-Poly1305, FTS5 operating on plaintext public columns.
* [ADR-0012](0012-eleven-built-in-categories-plus-cue-schema-for-custom.md) — category
  model; the `category` column indexed by `secrets_fts` carries values from
  this built-in enum plus custom category names.
* [ADR-0024](0024-mcp-adapter-consumes-companion-socket-client.md) — the
  `vault_search` MCP tool flows through the Companion Socket Client; the
  ranked search response contract defined here extends the
  `ListSecretsResponse` DTO surface in `crates/merkle-companion-client`.
* SQLite FTS5 `bm25()` auxiliary function:
  `https://sqlite.org/fts5.html#the_bm25_function`.
* SQLite FTS5 `highlight()` / `snippet()` auxiliary functions:
  `https://sqlite.org/fts5.html#the_highlight_function`.
* SQLite FTS5 content tables:
  `https://sqlite.org/fts5.html#_content_and_content_rowid_options`.
