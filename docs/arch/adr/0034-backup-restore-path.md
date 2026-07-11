---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0034 — Enable durable Backup restore-plan and apply path

## Context and Problem Statement

The Backup and Recovery domain, OpenAPI, MCP `vault_restore`, CLI restore, and
Gherkin `backup_and_restore.feature` describe a two-phase restore: preview a
`RestorePlan`, then apply after dual operator confirmation with HMAC
verification and modes overwrite, merge, and newest_wins.

In the running agent, Companion Socket handlers for
`POST /v1/backup/restore-plan` and `POST /v1/backup/restore` hard-return HTTP
501 via `restore_available() -> false`. Application commands exist but execute
restore only decrypts the age artifact and counts metadata; it does not fully
rehydrate secrets into storage. Operators therefore cannot recover vault state
from a Backup through any first-class product surface.

Feature `002-backup-restore-path` must close this gap without weakening
fail-closed security (integrity, confirmation, sealed-state gates).

## Decision Drivers

- Spec-first acceptance already exists in Gherkin; the product path must match it.
- Companion Socket is the sole inbound port; MCP and CLI must not bypass it.
- Tampered backups must never mutate the vault.
- Restore apply is integrity-affecting and needs dual operator confirmation.
- Half-wired restore (decrypt-only success) is worse than an honest 501.

## Considered Options

1. **Keep 501 indefinitely** until a future mega-release. Rejected: recovery is
   a core vault promise and surfaces already advertise the API.
2. **Enable handlers without durable plans** (stateless re-diff on apply).
   Rejected: plan expiry, conflict review, and audit correlation require a
   durable plan id between preview and apply.
3. **Enable durable restore-plan plus verified rehydration** (chosen). Turn
   `restore_available` on only when plan persistence, HMAC verification, and
   secret rehydration upserts are implemented and tested against Gherkin.

## Decision Outcome

Chosen option: "Enable durable restore-plan plus verified rehydration", because
it matches the domain contract and keeps fail-closed gates honest.

- Implement durable `RestorePlan` storage (or equivalent server-side plan
  registry with expiry) bound to snapshot id, mode, and computed actions.
- Verify Backup HMAC before any mutation; deny with
  `backup_integrity_check_failed` and audit outcome deny.
- Apply only with dual confirmation flags and a non-expired plan.
- Rehydrate secrets into storage according to mode; audit op restore
  allow or deny accurately.
- Flip `restore_available()` to true only behind that complete path.
- Disaster Recovery with Recovery Key remains a separate feature.

### Consequences

- Good: operators can preview and restore from age-encrypted Backups on the
  Master Key path; MCP and CLI stop failing at 501 for restore.
- Good: security gates (HMAC, confirmation, sealed) stay fail-closed.
- Bad: requires careful upsert and merge semantics and tests so apply is not
  metadata-only.
- Bad: increases operational surface (plan expiry, partial failure handling).

## Related

- Feature `002-backup-restore-path`
- [Backup and Recovery domain](../domain/backup-recovery.md)
- [backup_and_restore.feature](../specs/features/backup_and_restore.feature)
- [backup-restore-path.feature](../specs/features/backup-restore-path.feature)
- OpenAPI companion-socket backup paths
