---
status: accepted
date: 2026-05-24
deciders: [farchanjo]
consulted: []
informed: []
---

# 0026. Idempotent Bind and Session State Atomicity

## Context and Problem Statement

A live MCP session against the deployed `merkle-mcp` + `merkle-agent` stack
exhibits the following reproducible failure sequence:

```
1. vault_bind { label: "baremetal-v2" }  → ERROR: AlreadyBound
2. vault_list { }                         → ERROR: NamespaceNotBound
3. vault_search { query: "…" }            → ERROR: NamespaceNotBound
4. vault_bind { label: "eonf" }           → ERROR: AlreadyBound  (same process)
```

The contradiction is internally inconsistent: `AlreadyBound` asserts that a
namespace binding exists; `NamespaceNotBound` asserts that no binding exists.
Both errors are produced by the same MCP adapter process within the same
session, diverging on which of two distinct state stores they consult.

### Two state stores consulted by different tools

`vault.bind` is governed by `SessionState.namespace_bound` (a boolean in the
in-process `tokio::sync::RwLock<SessionState>` at
`crates/merkle-adapter-mcp/src/session.rs:36`). Tools such as `vault.list`
and `vault.search` are governed by `SessionState.namespace_id` (a `Option<Uuid>`
in the same struct, at `session.rs:23`), queried via `resolve_namespace()` at
`crates/merkle-adapter-mcp/src/tools/secrets.rs:153–157`.

These two fields can diverge when the bind operation is partially completed.

### Root cause: non-atomic bind with partial failure path

`vault_bind` in `crates/merkle-adapter-mcp/src/tools/identity.rs` (lines
173–208) executes three distinct phases in sequence:

**Phase 1 — session guard** (lines 174–178): acquires the `RwLock` write guard,
calls `session.bind(label)`, which sets `SessionState.namespace_bound = true`
and `SessionState.namespace_label = Some(label)`, then releases the lock.

**Phase 2 — Companion Socket call** (lines 185–192): calls
`client.create_session(CreateSessionRequest { … })`. This issues
`POST /v1/sessions` on the Companion Socket, which calls
`BindNamespaceCommand::execute()` in `crates/merkle-application/src/commands/bind_namespace.rs`.
The command unconditionally constructs a new `Namespace` with a fresh UUIDv7
(`ns.id = UuidV7::new()` at line 49), then calls `ctx.storage.put_namespace(&ns)`
which executes the SQL in `crates/merkle-adapter-sqlite/src/namespaces.rs:19–36`:

```sql
INSERT INTO namespaces (id, label, cwd_hash, policy_id, dek_version, created_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
ON CONFLICT(id) DO UPDATE SET …
```

The `ON CONFLICT` clause targets the `id` column. The `namespaces` table schema
(`crates/merkle-adapter-sqlite/src/migrations/*.sql`) declares
`label TEXT NOT NULL UNIQUE`. When the label was already inserted by a prior
bind (from a previous session or a previous first-bind attempt), the INSERT
raises a `SQLITE_CONSTRAINT_UNIQUE` error on `label`. This maps to
`StorageError` → `AppError::Storage` → HTTP 500 (not 409) in
`crates/merkle-adapter-companion-socket/src/problem.rs:259–266`. The
`client_error_to_mcp` mapping in `crates/merkle-adapter-mcp/src/errors.rs:101`
receives an `Http { status: 500, … }` and returns a generic server error.

**Phase 3 — session commit** (lines 194–197): calls `session.set_binding(
resp.namespace_id, resp.session_id)`, which populates `SessionState.namespace_id`
and `SessionState.session_id`.

When Phase 2 fails (which it does every time the label already exists in
storage), the `?` operator at line 192 short-circuits the function — Phase 3
is never reached. `namespace_bound` is `true`; `namespace_id` is `None`.

**Subsequent effects**:

- Any `vault.list`, `vault.search`, `vault.put`, or other tool that calls
  `resolve_namespace()` reads `session.namespace_id()` → `None` → returns
  `NamespaceNotBound`.
- Any repeat call to `vault.bind` reads `session.namespace_bound = true` →
  returns `AlreadyBound`.
- The session is permanently poisoned; no recovery path exists short of
  restarting the MCP process.

### Why this surfaces on reconnect

`BindNamespaceCommand` performs an unconditional `put_namespace` without first
checking whether a namespace with the given label already exists. Namespaces
persist across sessions in SQLite; their labels carry a `UNIQUE` constraint.
The first session that binds label `"baremetal-v2"` succeeds. Every subsequent
MCP process that calls `vault_bind { label: "baremetal-v2" }` will fail at the
SQLite layer and poison its `SessionState`.

This contradicts ADR-0008 §Binding algorithm, step 4, which states that
`vault.bind(label)` in the MCP session replaces the label for the duration of
that session — implying that binding a previously-created namespace label is a
valid and expected operation.

### Relationship to ADR-0024 §Note 1

ADR-0024 Note 1 flagged that `vault.bind` maps to `BindNamespaceCommand` while
`POST /v1/sessions` uses `CreateSessionRequest`, and that PR2 must reconcile
these representations. The PR2 reconciliation introduced `create_session` as
the unified path but left `BindNamespaceCommand` in a create-only posture
(no upsert-by-label). The reconciliation is incomplete: the command lacks the
"resolve existing namespace" branch that idempotency requires.

## Decision Drivers

* **Idempotent bind semantics**: calling `vault.bind` with a label that
  already exists in storage must succeed and resolve to the existing namespace,
  not attempt a conflicting insert. ADR-0008 §step 4 implies this semantics.
* **Session state atomicity**: `SessionState.namespace_bound` and
  `SessionState.namespace_id` must always agree — both set or both unset.
  A partial-failure path that sets one but not the other is a class of
  correctness bugs, not just this instance.
* **Error model coherence with ADR-0024 §Note 1**: the bind surface must
  return a coherent error (either clean success or a well-typed failure) that
  does not leave the session in an unrecoverable half-bound state.
* **No breaking change to ADR-0002 single-writer invariant**: the fix must
  not introduce concurrent SQLite writes.

## Considered Options

### Option A: Make `BindNamespaceCommand` idempotent — upsert-by-label

Change `BindNamespaceCommand::execute()` to attempt `get_namespace_by_label`
first; if a row exists, return it directly without a new INSERT. If no row
exists, insert as today. This eliminates the `UNIQUE` constraint violation at
the SQLite layer.

Additionally, change the session guard in `vault_bind` to not set
`namespace_bound = true` until Phase 3 (`set_binding`) succeeds, using a
two-phase commit pattern: set the label in a staging field only; promote to
`namespace_bound = true` atomically with `set_binding` when the socket call
succeeds.

### Option B: Remove the `AlreadyBound` concept — permit unlimited rebind

Remove `SessionState.namespace_bound` and the "at most once per session"
invariant. Allow `vault.bind` to be called multiple times; each call issues
`POST /v1/sessions` and overwrites `namespace_id` / `session_id` in
`SessionState`. The existing namespace data in storage is not touched.

### Option C: Introduce an explicit `vault.rebind` operation

Keep the "at most once" invariant for `vault.bind`. Introduce a new
`vault.rebind` MCP tool that is allowed at any point and replaces the session
binding. `vault.rebind` would also be idempotent at the storage layer via
the same upsert-by-label mechanism in Option A.

## Decision Outcome

Chosen option: **Option A — idempotent `BindNamespaceCommand` + two-phase
commit in `vault_bind`**.

Option B is rejected because removing the single-bind invariant would allow
accidental namespace switching mid-session. A session that lists from namespace
A, then rebinds to B, then writes would silently scatter secrets across
namespaces without any observable transition. The invariant protects against
this class of operator error.

Option C is rejected because introducing a new MCP tool adds surface area
without solving the underlying atomicity problem. Any implementation of
`vault.rebind` must still solve the two-phase commit and the idempotent
storage upsert; Option C is Option A plus new tooling. It can be reconsidered
as a follow-on if explicit runtime rebind becomes a documented operator need.

### Decision detail

**Storage fix — upsert-by-label in `BindNamespaceCommand`**:

`BindNamespaceCommand::execute()` in
`crates/merkle-application/src/commands/bind_namespace.rs` must be changed to:

1. Query `ctx.storage.get_namespace_by_label(&self.label)` before inserting.
2. If a row exists, return `BindNamespaceOutput { namespace_id: existing.id,
   label: existing.label }` without any INSERT or audit entry (the bind was
   already recorded in a prior session).
3. If no row exists, proceed with the current INSERT path and audit entry.

This makes the command safe to call from any number of MCP sessions that bind
the same label, mirroring the behaviour of `get-or-create` patterns common in
idempotent REST endpoints.

**SQL fix — `ON CONFLICT(label)` instead of `ON CONFLICT(id)` in
`put_namespace`**:

The upsert SQL in `crates/merkle-adapter-sqlite/src/namespaces.rs:19–36`
must be changed to target the `label` column:

```sql
INSERT INTO namespaces (id, label, cwd_hash, policy_id, dek_version, created_at)
VALUES (?1, ?2, ?3, ?4, ?5, ?6)
ON CONFLICT(label) DO UPDATE SET
    cwd_hash    = excluded.cwd_hash,
    policy_id   = excluded.policy_id,
    dek_version = excluded.dek_version
```

When a label already exists, this updates the mutable fields (cwd_hash,
policy_id, dek_version) without creating a new UUID. The caller must then
SELECT the row to obtain the canonical `id` for the `BindNamespaceOutput`.
Alternatively, the command can use the get-or-create pattern described above
and avoid the conflict entirely.

**Adapter fix — two-phase commit in `vault_bind`**:

`vault_bind` in `crates/merkle-adapter-mcp/src/tools/identity.rs` must be
restructured so that `namespace_bound` is set to `true` only after
`set_binding` succeeds:

```
[BEFORE]
Phase 1: set namespace_bound=true, namespace_label=Some(label)
Phase 2: client.create_session(...)  ← can fail, leaving bound=true, id=None
Phase 3: session.set_binding(namespace_id, session_id)

[AFTER]
Phase 1: check namespace_bound; if already true, return AlreadyBound early
Phase 2: client.create_session(...)  ← if fail, namespace_bound stays false
Phase 3: set namespace_bound=true, namespace_label=Some(label),
         namespace_id=Some(id), session_id=Some(sid) — all in one write lock
```

`SessionState::bind` must be split: the guard check and the state commit must
be separable. The existing `bind()` method combines both in one call. The
refactored path calls a new `is_bound()` guard check first, then defers the
`namespace_bound = true` assignment to a combined `commit_binding(label, id,
session_id)` method that populates all four fields atomically.

**OpenAPI contract**: `POST /v1/sessions` currently documents only `201` and
`503` responses. The `503` maps to `AgentSealed`. With the idempotent fix, the
only failure mode for a valid label is `AgentSealed`; no 500 is expected.
The existing `201` response is returned for both new and existing labels. No
OpenAPI structural change is required; the semantic of `201` is extended to
mean "session created or re-associated". A description clarification in the
OpenAPI file is appropriate but not a breaking change.

### Consequences

* Good, because binding a label that already exists in storage succeeds
  without any retry or process restart. The session enters a fully bound
  state on the first call.
* Good, because `SessionState.namespace_bound` and `SessionState.namespace_id`
  are always mutually consistent — both set or both unset after any single
  `vault_bind` invocation completes.
* Good, because the "at most once per session" semantics of `vault.bind` are
  preserved. The guard check fires before the socket call, so no double-bind
  within a single session is possible.
* Good, because the fix is entirely internal to the adapter and the application
  command; no MCP protocol change, no new MCP tool, no new socket endpoint.
* Bad, because `BindNamespaceCommand` changes from a pure-create command to a
  get-or-create command. Callers that relied on a consistent 500 "label
  already exists" error (if any) will no longer see that error. No such caller
  exists in the current workspace.
* Bad, because the SQL `ON CONFLICT(label)` upsert silently updates
  `cwd_hash` and `dek_version` when the label already exists. A future
  invariant that "once created, a namespace's DEK version is immutable" would
  require a separate guard. This is not yet an invariant; it is noted as a
  risk for Phase 7.

## Validation

Each fix lands with a failing test authored before any source-code edit
(impl-guard contract per ADR-0018).

1. **Adapter atomicity regression** —
   `crates/merkle-adapter-mcp/tests/mcp_integration.rs`: add a test
   `vault_bind_socket_failure_leaves_session_unbound` that:
   - constructs an `unreachable_server()` (socket absent → `AGENT_UNREACHABLE`).
   - calls `vault.bind` once; the socket call fails with `AGENT_UNREACHABLE`.
   - asserts that `session.namespace_id()` is `None` (not poisoned).
   - asserts that a second `vault.bind` call returns `AGENT_UNREACHABLE`,
     not `ALREADY_BOUND` (session is not permanently locked).
   This test FAILS on the current code because `namespace_bound` is set in
   Phase 1 before the socket call, and the second bind is rejected with
   `ALREADY_BOUND` instead of proceeding to the socket.

2. **Idempotent command unit test** —
   `crates/merkle-application/tests/use_cases.rs`: add a test
   `bind_namespace_same_label_twice_is_idempotent` that:
   - binds label `"acme"` via `BindNamespaceCommand`; captures `namespace_id`.
   - binds label `"acme"` again; asserts the second output has the same
     `namespace_id` (not a new UUID).
   - asserts the SQLite `namespaces` table still contains exactly one row
     for label `"acme"`.

3. **End-to-end bind-then-list smoke** —
   `bin/merkle-cli/tests/cli_smoke.rs` or equivalent BDD step:
   - unseal the vault.
   - call `vault.bind { label: "reconnect-test" }` → assert success.
   - call `vault.list { }` → assert success (not `NamespaceNotBound`).
   - restart the MCP process (simulate reconnect).
   - call `vault.bind { label: "reconnect-test" }` again → assert success
     (not `AlreadyBound`).
   - call `vault.list { }` → assert success.

4. **Gherkin coverage** — `docs/arch/specs/features/session_bind_idempotency.feature`
   (introduced by this ADR). The `lint_features` lane must pass with the new
   file present.

`spec validate` must remain 9/9 green throughout every PR in this batch.

After all PRs merge, re-run the live smoke test from ADR-0025 in order:

```
merkle doctor
merkle bind baremetal-v2        ← first session
merkle list
(restart mcp process)
merkle bind baremetal-v2        ← second session, same label
merkle list
merkle bind eonf                ← second session, different label → AlreadyBound expected
```

Assert that steps 1–6 produce accurate output, and that step 7 (`bind eonf`
after `bind baremetal-v2` in the same session) correctly returns `AlreadyBound`.

## More Information

* [ADR-0002](0002-adopt-agent-plus-mcp-adapter-topology.md) — single-writer
  SQLite invariant; the fix must not introduce concurrent writers. The
  get-or-create path in `BindNamespaceCommand` is a read-then-conditional-write
  under the daemon's single-writer ownership; no invariant is violated.
* [ADR-0008](0008-cwd-bound-namespace-with-overrides.md) — binding algorithm
  §step 4: "`vault.bind(label)` in the MCP session replaces the label for the
  duration of that session." Idempotent bind is a prerequisite for this
  contract to hold across process restarts.
* [ADR-0024](0024-mcp-adapter-consumes-companion-socket-client.md) — §Note 1:
  "PR2 must reconcile `BindNamespaceCommand` vs `CreateSessionRequest`." This
  ADR documents the correctness gap that remained after that reconciliation.
* [ADR-0025](0025-post-phase-2-cosmetic-cleanup.md) — §Note 1: "`vault.bind`
  vs `CreateSessionRequest` reconciliation." The present bug is a direct
  consequence of the incomplete reconciliation tracked there.
* `crates/merkle-adapter-mcp/src/tools/identity.rs` — `vault_bind`
  implementation; the non-atomic Phase 1/Phase 2/Phase 3 sequence is the
  proximate defect site.
* `crates/merkle-adapter-mcp/src/session.rs:64–71` — `SessionState::bind`:
  the combined guard-and-commit that must be split for the two-phase fix.
* `crates/merkle-application/src/commands/bind_namespace.rs:49–54` — the
  unconditional `Namespace::new()` + `put_namespace` that produces the
  `UNIQUE` constraint violation on `label`.
* `crates/merkle-adapter-sqlite/src/namespaces.rs:19–36` — `put_namespace`
  SQL: `ON CONFLICT(id)` does not handle the `UNIQUE` constraint on `label`,
  causing a 500 instead of a clean idempotent return.
* `crates/merkle-adapter-companion-socket/src/problem.rs:259–266` —
  `AppError::Storage` maps to HTTP 500, not 409; nothing in the stack converts
  the constraint violation into a typed "label exists" error.
