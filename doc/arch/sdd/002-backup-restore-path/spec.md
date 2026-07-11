---
id: 019f4f27-c79f-7063-b371-e7649adecae6
number: 002
slug: backup-restore-path
status: implemented
created_at: 2026-07-11T03:10:34.911726Z
---
# Feature Specification: Backup Restore Path

Feature: 002-backup-restore-path
Created: 2026-07-11

## User Stories

- As a vault operator I want to preview a restore from an age-encrypted Backup so that I can see adds, overwrites, skips, and conflicts before any secret is mutated.
- As a vault operator I want to apply a confirmed restore plan so that secrets return to a known good snapshot without silent partial writes.
- As a security reviewer I want restore to stay fail-closed until durable plan storage, HMAC verification, and dual operator confirmation are enforced so that a tampered or unconfirmed restore cannot mutate the vault.

## Context

Existing acceptance suite (keep as source of truth for lifecycle scenarios):

- [`docs/arch/specs/features/backup_and_restore.feature`](../../specs/features/backup_and_restore.feature)

Feature-scoped scenarios for the product enablement gate:

- [`docs/arch/specs/features/backup-restore-path.feature`](../../specs/features/backup-restore-path.feature)

Domain narrative:

- [`docs/arch/domain/backup-recovery.md`](../../domain/backup-recovery.md)

Current code gap this feature closes:

- Companion Socket `POST /v1/backup/restore-plan` and `POST /v1/backup/restore` return HTTP 501 because `restore_available()` is hard-coded false.
- `RestorePlanCommand` and `ExecuteRestoreCommand` exist; execute decrypts the age artifact but does not fully rehydrate secrets into storage.
- MCP `vault_restore` and CLI restore call the Companion Socket client and inherit the 501 gate.

Out of scope: Disaster Recovery via Recovery Key re-wrap (`disaster_recovery.feature`).

## Functional Requirements

1. While the vault is Unsealed, `POST /v1/backup/restore-plan` accepts a known backup snapshot filename or snapshot id and a restore mode in the closed set overwrite, merge, newest_wins and returns HTTP 200 with a durable RestorePlan preview (plan id, mode, per-secret actions, conflicts, expires_at) instead of 501.
2. Restore plan generation decrypts the Backup with the active Master Key age identity, validates the Backup HMAC Signature before any vault mutation, and rejects tampered artifacts with error code backup_integrity_check_failed and audit op restore, outcome deny, denial_reason backup_integrity_check_failed.
3. Restore modes match the domain contract: overwrite replaces local secrets from the Backup; merge imports only absent or Backup-newer secrets while preserving newer local versions; newest_wins resolves conflicts by the domain timestamp policy.
4. A restore plan preview never mutates the vault database and never appends a successful restore audit entry; it only returns the diff.
5. `POST /v1/backup/restore` applies a previously created, non-expired plan id only when both operator confirmation flags are true (operator_confirmation.slash_command and operator_confirmation.oob_ack); otherwise it returns 403 OperatorConfirmationRequired.
6. Successful apply rehydrates secret material and public metadata into storage for the target namespace(s), records audit op restore with outcome allow, and reports the count of secrets restored as the number of applied rows.
7. Expired plans are rejected with a typed RestorePlanExpired error and leave the vault unchanged.
8. MCP vault_restore and CLI merkle restore succeed against a local Unsealed agent once the Companion Socket path is enabled; they surface integrity and confirmation failures without leaking Backup plaintext or age identity material.
9. Backup creation triggers (manual, anacron, change-triggered) remain available; this feature does not regress vault_backup or POST /v1/backup success paths.
10. Enabling restore_available requires plan persistence, HMAC verification, and rehydration that upserts real secret rows — not metadata-only counts after decrypt.

## Security Requirements

- **Data sensitivity/classification.** Restore reads age-encrypted Backup ciphertext (Secret private material, public metadata, optional audit snapshot) and writes Secret private blobs and metadata into SQLite. Classification is vault-secret at highest sensitivity. Plan previews expose handles, versions, and action labels only — never plaintext secret bodies over MCP or logs.
- **Authentication/authorization.** Companion Socket remains the sole inbound port with peer-cred. Restore apply requires dual operator confirmation (slash command and OOB ack). Restore is not available while Sealed. MCP tools must not bypass confirmation gates.
- **Input validation.** Snapshot filename, plan id, and mode are closed, bounded inputs. Unknown snapshot returns 404. Malformed mode returns 400. Tampered Backup fails integrity before mutation. Plan expiry is enforced server-side.
- **Cryptography in transit/at rest.** Backups stay age-encrypted at rest with dual recipients (Master public key and Recovery Public Key). This feature uses the Master Key age identity for the normal restore path. HMAC Signature over the backup payload or header is verified before apply. Age identity material is never logged; Debug redacts it.
- **Logging/audit.** Append audit entries for restore deny (integrity, confirmation) and restore allow (apply). Log fields include plan id, mode, snapshot id, and counts — never ciphertext, plaintext, or age secret keys.
- **Error-handling information exposure.** Client-visible errors use stable problem types (backup_integrity_check_failed, OperatorConfirmationRequired, plan expired, not found). Messages must not include decrypted payload excerpts or key material.

## Acceptance Scenarios

Given the Vault Agent is Unsealed and a valid Backup file exists in the configured target directory
When the operator creates a restore plan with mode merge
Then the agent returns HTTP 200 with a plan id, conflict list, and expires_at
And no vault secret rows change
And no successful restore audit entry is appended

Given a valid non-expired restore plan and both operator confirmation flags are true
When the operator calls execute restore with that plan id
Then secrets from the Backup are rehydrated according to the plan mode
And an Audit Entry with op restore and outcome allow is appended
And the response reports secrets_restored equal to the number of applied rows

Given a Backup file that was modified after creation
When the operator creates or executes a restore against that file
Then the agent rejects with backup_integrity_check_failed
And no vault mutations occur
And an Audit Entry with op restore, outcome deny, and denial_reason backup_integrity_check_failed is appended

Given a restore plan whose expires_at is in the past
When the operator calls execute restore
Then the agent rejects with a plan-expired error
And the vault is unchanged

Given operator_confirmation.slash_command or oob_ack is false
When the operator calls execute restore
Then the agent returns 403 OperatorConfirmationRequired
And the vault is unchanged

Given merge mode and a local secret newer than the Backup version
When the operator applies the restore plan
Then the newer local version is preserved
And only absent or Backup-newer secrets are imported

## Observability

- Metric: restore_plan_created_total, restore_apply_total with outcome label, restore_integrity_failures_total; bounded labels only (outcome, mode).
- Log: structured events for plan create, apply start and end, integrity failure; redacted keys.
- Trace: spans backup.restore_plan and backup.restore_apply with plan_id and snapshot_id attributes; no high-cardinality secret handles as metric labels.
- Operator signal: merkle doctor and agent status report whether restore capability is enabled; CLI restore no longer stops at 501 once enabled.

## Schema contracts

- Feature posture: [`docs/arch/schemas/backup-restore-path.cue`](../../schemas/backup-restore-path.cue)
- Domain: `docs/arch/schemas/backup_recovery/` (including restore_plan)
- OpenAPI: `docs/arch/integrations/openapi/companion-socket.yaml` paths POST /v1/backup/restore-plan and POST /v1/backup/restore

## Out of scope

- Disaster Recovery ceremony with Recovery Key and Master Key re-wrap
- Remote backup transport or off-host replication
- Changing dual-recipient age policy or Backup filename conventions

## Related

- ADR-0034 — enable durable restore-plan path
- Domain: Backup and Recovery
- Gherkin: backup_and_restore.feature, backup-restore-path.feature
- Code anchors: RestorePlanCommand, ExecuteRestoreCommand, companion-socket handlers/backup.rs restore_available

## Clarifications

Resolved during `speckit clarify` (no open TBDs for planning).

### C1 — Durable RestorePlan storage

**Decision:** Persist `RestorePlan` rows in SQLite via `merkle-adapter-sqlite`,
not process-local memory and not the filesystem.

- New table (migration) stores plan id (independent UUIDv7), source backup
  snapshot id, target namespace, mode, conflict list (JSON), validated_at,
  expires_at, applied_at (nullable).
- Port methods on `merkle-ports` storage: `put_restore_plan`,
  `get_restore_plan`, `mark_restore_plan_applied` (or equivalent).
- Apply looks up by **plan id**, never reuses snapshot id as plan id (current
  handler bug: `body.plan_id` parsed as `backup_snapshot_id`).
- Persistence is required before `restore_available()` may return true
  (ADR-0034).

### C2 — Plan TTL

**Decision:** Domain default **10 minutes** from `validated_at`, matching
`RestorePlanner::PLAN_EXPIRY_MINUTES` and domain doc invariant.

- Server enforces expiry on apply; expired plans yield typed
  `RestorePlanExpired` and leave the vault unchanged.
- Configurability beyond the domain constant is out of scope for Feature 002.
- Expired rows may remain for audit correlation; they must not apply.

### C3 — Rehydration scope

**Decision:** Full secret material + public metadata upsert for the plan's
target namespace(s) — not decrypt-only metadata counts.

- Backup plaintext format remains the JSON `Vec` of secrets written by
  `TriggerBackupCommand` (same serde shape).
- Plan generation decrypts (after HMAC verify), enumerates backup-side
  handles/timestamps, and diffs against live secrets so conflicts are real.
- Apply loads the durable plan, re-reads and re-verifies the artifact, then
  upserts rows according to mode; `secrets_restored` equals applied row count.
- Multi-namespace whole-vault restore and Disaster Recovery re-wrap remain
  out of scope; default namespace selection stays as today until multi-ns is
  specified elsewhere.

### C4 — HMAC location and verify order

**Decision:** Encrypt-then-MAC over **age ciphertext** (ADR-0006 amendment),
not a separate MAC of unencrypted header at restore time.

- Tag lives on the `Backup` aggregate (`hmac`) and `BackupArtifact.hmac_tag`
  in SQLite backup metadata (already written by `TriggerBackupCommand`).
- On-disk file is pure age ciphertext; restore recomputes
  `HmacSignature::compute(vault_hmac_key, ciphertext)` and constant-time
  compares to the stored tag **before** `age_decrypt`.
- Mismatch → `backup_integrity_check_failed`, audit op `restore` outcome
  `deny`, zero vault mutations. No plaintext in logs.

### C5 — Product restore modes vs domain enums

**Decision:** Wire product modes `overwrite | merge | newest_wins` as follows:

| Product mode | Apply semantics |
|---|---|
| `overwrite` | Every backup secret replaces local by handle; local-only secrets untouched unless domain later adds delete-on-overwrite (not in this feature). |
| `merge` | Import absent handles and backup-newer versions; preserve newer local versions (product merge). |
| `newest_wins` | Resolve each conflict by domain timestamp policy (newer `created_at` / version timestamp wins). |

Map DTO → domain carefully in the Companion Socket adapter; extend
`RestoreMode` or apply-path branching if current enums cannot express
force-overwrite without timestamp compare. Do not invent a fourth product
mode in OpenAPI.

### C6 — Audit on plan vs apply

**Decision:** Plan preview must **not** append a successful restore audit
(`outcome allow`). Fix the current `RestorePlanCommand` allow-audit so
preview stays non-mutating and non-success-audited. Integrity failures and
apply allow/deny audit as specified in Functional Requirements.

### C7 — Enablement gate

**Decision:** Flip `restore_available()` to `true` only in the same change set
that lands durable plans, HMAC verify-before-decrypt, dual confirmation
(already partially in handler), and real secret upserts — never earlier.
