# Implementation Plan: Backup Restore Path

## Goal

Enable Companion Socket `POST /v1/backup/restore-plan` and
`POST /v1/backup/restore` end-to-end: durable `RestorePlan` storage, Backup
HMAC verification before decrypt, dual operator confirmation on apply, and
real secret rehydration into SQLite. Flip `restore_available()` only when that
path is complete so MCP `vault_restore` and CLI restore stop inheriting HTTP
501. Disaster Recovery remains out of scope.

## Approach

1. **Ports + SQLite** — migrate `restore_plans` table; implement put/get/mark
   applied on the storage port and `merkle-adapter-sqlite`.
2. **Domain** — keep `RestorePlanner` TTL (10 min); align product modes
   (overwrite / merge / newest_wins) with conflict resolution and apply
   semantics (clarification C5); pure helpers for expiry and applied guards.
3. **Application** — rewrite `RestorePlanCommand` to verify HMAC, decrypt,
   build real per-handle diff, persist plan, no allow-audit on preview; rewrite
   `ExecuteRestoreCommand` to load plan by plan id, enforce expiry and
   not-yet-applied, re-verify HMAC, upsert secrets by mode, audit allow/deny
   with accurate `secrets_restored`.
4. **Companion Socket** — wire handlers to plan id (not snapshot id), load
   Master Key age identity (no placeholder), map modes and problems; flip
   `restore_available()` true after the path is real.
5. **MCP + CLI** — confirm client paths already call socket endpoints; surface
   integrity / confirmation / expired errors without leaking material; no
   bypass of dual confirmation.
6. **Tests** — unit (planner, HMAC fail, expiry), adapter integration (plan
   round-trip), BDD / Gherkin scenarios in
   `backup-restore-path.feature` and relevant
   `backup_and_restore.feature` steps; regression that backup create still
   succeeds.

## Technical Design

### Architecture (hexagonal)

```text
CLI / MCP  →  Companion Socket (sole inbound)
                 handlers/backup.rs
                      │
         RestorePlanCommand / ExecuteRestoreCommand  (merkle-application)
                      │
         RestorePlanner + RestorePlan               (merkle-domain-backup-recovery)
                      │
         StoragePort + CryptoPort                   (merkle-ports)
                      │
         merkle-adapter-sqlite / merkle-adapter-crypto / keychain
```

### Crate map

| Layer | Crate / path | Work |
|---|---|---|
| Inbound adapter | `crates/merkle-adapter-companion-socket/src/handlers/backup.rs` | Remove 501 gate after readiness; parse `plan_id` as plan UUIDv7; dual confirmation already present; resolve Master age identity; map problem types (`backup_integrity_check_failed`, `RestorePlanExpired`, `OperatorConfirmationRequired`); populate action counts on plan response from real plan data |
| Application | `crates/merkle-application/src/commands/restore_plan.rs` | HMAC verify → decrypt → list backup secrets → `RestorePlanner::plan` → `put_restore_plan`; no allow audit on success |
| Application | `crates/merkle-application/src/commands/execute_restore.rs` | `get_restore_plan` by plan id; reject expired / applied; re-verify HMAC; decrypt; mode-aware upsert; `mark_restore_plan_applied`; audit allow with real count; integrity deny audit |
| Domain | `crates/merkle-domain-backup-recovery` | `RestorePlan`, `RestorePlanner`, modes; optional `is_expired(now)` / applied invariant helpers; mode mapping docs for product modes |
| Ports | `crates/merkle-ports/src/storage.rs` | `put_restore_plan`, `get_restore_plan`, `mark_restore_plan_applied`; not-found and already-applied map to storage errors consumed by application |
| SQLite | `crates/merkle-adapter-sqlite` | Migration `006_restore_plans.sql` (or next free number); `restore_plans` module; storage trait impl |
| Crypto | `crates/merkle-adapter-crypto` + `merkle-types::HmacSignature` | Reuse `HmacSignature::compute` + constant-time eq; `age_decrypt` after verify |
| MCP | `crates/merkle-adapter-mcp` | Ensure `vault_restore` uses socket client; error mapping only |
| CLI | `bin/merkle-cli` | Restore plan/apply subcommands already route to socket; confirm UX for confirmation flags |
| Tests | `merkle-domain-backup-recovery` unit, `merkle-adapter-sqlite` integration, `merkle-bdd` / feature files under `docs/arch/specs/features/` | See tasks |

### Durable plan schema (SQLite)

```sql
CREATE TABLE IF NOT EXISTS restore_plans (
  id BLOB NOT NULL PRIMARY KEY,           -- plan UUIDv7
  source_backup_id BLOB NOT NULL,         -- backup snapshot_id
  namespace_id BLOB NOT NULL,
  mode TEXT NOT NULL,
  conflicts_json TEXT NOT NULL,
  validated_at TEXT NOT NULL,             -- RFC 3339
  expires_at TEXT NOT NULL,
  applied_at TEXT,                        -- NULL until applied
  plan_json TEXT NOT NULL                 -- full RestorePlan snapshot for apply
);
CREATE INDEX IF NOT EXISTS idx_restore_plans_ns ON restore_plans(namespace_id);
CREATE INDEX IF NOT EXISTS idx_restore_plans_exp ON restore_plans(expires_at);
```

Exact column set may fold `plan_json` alone if simpler; must support get-by-id
and applied_at transition without rewriting history of other fields.

### Restore-plan sequence

1. Unsealed required.
2. Resolve backup by snapshot filename or snapshot id (existing list_backups).
3. Read artifact bytes from `backup.artifact.path`.
4. `expected = backup.hmac` (or `artifact.hmac_tag`); recompute MAC over
   ciphertext with vault HMAC key; fail closed on mismatch (deny audit).
5. `age_decrypt` with Master Key age identity from unseal/keychain.
6. Deserialize `Vec` secrets (same shape as backup create).
7. Build `(Handle, timestamp)` slices; `RestorePlanner::plan(...)`.
8. Persist plan; return DTO with plan_id, mode, counts, conflicts, expires_at.
9. No secret row mutations; no restore allow audit.

### Restore-apply sequence

1. Unsealed required; handler requires both confirmation flags (403 otherwise).
2. Load plan by plan id; 404 if missing; typed expired if `now > expires_at`;
   reject if `applied_at` set (idempotent re-apply denied).
3. Reload backup record and file; HMAC verify again before decrypt.
4. Decrypt; for each backup secret, apply per mode (C5); count applied rows.
5. Mark plan applied; audit restore allow; return `secrets_restored`.

### HMAC location (C4)

Encrypt-then-MAC: tag stored in SQLite backup metadata with the aggregate;
on-disk `.merkle.age` is ciphertext only. Verify before decrypt always.

### Enablement

```rust
fn restore_available() -> bool {
    true // only after plan persist + HMAC + rehydration land together
}
```

Prefer a single PR/commit train that lands storage + commands + gate flip so
half-wired 200s never ship.

### Error / problem mapping

| Condition | HTTP / problem |
|---|---|
| Restore not enabled | 501 (pre-flip only) |
| Snapshot unknown | 404 |
| Bad mode | 400 |
| HMAC mismatch | `backup_integrity_check_failed` + deny audit |
| Missing confirmation | 403 `OperatorConfirmationRequired` |
| Plan expired | typed `RestorePlanExpired` |
| Plan unknown | 404 |
| Sealed | sealed problem (existing) |

## Security

- Fail closed: sealed, HMAC fail, confirmation fail, expired plan → no mutate.
- Dual confirmation stays on apply only; MCP/CLI must not invent a side path.
- Logs/traces: plan_id, snapshot_id, mode, counts — never ciphertext, plaintext
  secret bodies, or age identity material (`Debug` redacts age keys).
- Constant-time HMAC compare via existing type/`subtle` patterns.
- Artifact path is server-resolved from backup records; do not accept arbitrary
  absolute paths from untrusted clients.

## Observability

- Metrics: `restore_plan_created_total`, `restore_apply_total{outcome}`,
  `restore_integrity_failures_total` (bounded labels).
- Spans: `backup.restore_plan`, `backup.restore_apply` with plan_id /
  snapshot_id attributes.
- Doctor / agent status: report restore capability true once gate flipped.
- Audit: integrity deny + apply allow/deny; no plan-phase allow (C6).

## Rollout

1. Ship corpus (this plan/tasks) on branch `002-backup-restore-path`.
2. Implement storage → commands → handlers → tests; flip gate last.
3. Run Gherkin BDD and unit suites; `make test` / feature acceptance.
4. Accept ADR-0034 (proposed → accepted) when implementation merges.
5. No migration waiver: empty vaults get empty `restore_plans`; no backfill.

## Tasks mapping

See `tasks.md` (T1–T14). Dependency spine: T1 → T2 → T3–T5 → T6 → T7–T8 →
T9 → T10–T12 → T13 → T14.
