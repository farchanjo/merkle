# Tasks: Backup Restore Path

## Task list

- [x] T1 Add SQLite migration for `restore_plans` and document schema in adapter
      module comments (`merkle-adapter-sqlite/src/migrations/`, next free id).
- [x] T2 Extend `merkle-ports` storage trait with `put_restore_plan`,
      `get_restore_plan`, and `mark_restore_plan_applied` (or equivalent named
      methods); not-found and already-applied map to storage errors consumed by
      application commands.
- [x] T3 Implement restore-plan persistence in `merkle-adapter-sqlite` (module +
      trait impl) with integration tests for round-trip, get-missing, and
      mark-applied.
- [x] T4 Domain alignment in `merkle-domain-backup-recovery`: product mode
      semantics (overwrite / merge / newest_wins), expiry helper
      (`is_expired`), applied guard, and unit tests for planner TTL + mode
      resolutions used by rehydration.
- [x] T5 HMAC verify helper path for backup ciphertext (application or domain
      pure function using `HmacSignature::compute` + constant-time compare);
      unit test: matching tag passes, flipped bit fails with integrity code.
- [x] T6 Rewrite `RestorePlanCommand` (`merkle-application/src/commands/restore_plan.rs`):
      load backup → read file → verify HMAC → decrypt with Master age identity →
      deserialize secrets → `RestorePlanner::plan` with real backup-side handles →
      persist plan → return plan; remove success restore allow-audit on preview;
      deny audit on integrity failure.
- [x] T7 Rewrite `ExecuteRestoreCommand` (`execute_restore.rs`): load plan by
      plan id → reject expired/applied → re-verify HMAC → decrypt → mode-aware
      secret upserts into storage → count applied rows → mark applied → audit
      allow; no placeholder age identity.
- [x] T8 Wire Companion Socket `handlers/backup.rs`: map product modes; use plan
      id (not snapshot id) on apply; resolve real Master age identity; populate
      plan response counts from plan data; dual confirmation remains 403;
      flip `restore_available()` to true only after T6–T7 behave correctly.
- [x] T9 MCP adapter (`merkle-adapter-mcp`): ensure `vault_restore` / plan
      surfaces call socket client only; map integrity, confirmation, and expired
      errors without leaking plaintext or age material.
- [x] T10 CLI (`bin/merkle-cli` restore plan/apply): end-to-end against unsealed
      local agent once gate is on; confirmation flags required for apply; no
      silent bypass.
- [x] T11 Unit/integration tests for commands (plan non-mutating, apply
      rehydrates, merge preserves newer local, expired plan, confirmation
      denied at handler, integrity fail). Prefer existing test harness patterns
      in `merkle-application` / sqlite tests.
- [x] T12 BDD / Gherkin: implement or wire steps for
      `docs/arch/specs/features/backup-restore-path.feature` and keep
      `backup_and_restore.feature` lifecycle scenarios green under
      `merkle-bdd` (or project BDD entrypoint).
- [x] T13 Regression: `POST /v1/backup` and MCP/CLI backup triggers still
      succeed (dual recipients, HMAC record, list snapshots); doctor/status
      reports restore capability when enabled.
- [x] T14 Accept ADR-0034 and mark feature ready for implement-phase merge
      criteria: `speckit validate` clean for corpus; implementation PR
      separately runs `make test` / lint.

## Dependencies

```text
T1 → T2 → T3
T4, T5 free after clarify (parallel with T1–T3)
T3 + T4 + T5 → T6 → T7 → T8
T8 → T9, T10
T6, T7, T8 → T11, T12
T8 → T13
T11 + T12 + T13 → T14
```

## Acceptance

- All tasks checked before feature status moves to implemented.
- `restore_available()` true only with durable plans + HMAC + rehydration.
- Gherkin product gate scenarios pass; no 501 on restore-plan/restore when
  unsealed with valid backup and confirmations.
- `speckit validate` remains 0 findings for the SDD half; code quality gates
  on the implementation half.
