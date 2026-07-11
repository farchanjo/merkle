---
status: accepted
date: 2026-07-10
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0031 — Idle re-lock supervisor with post-auth activity touch

## Context and Problem Statement

While the vault is Unsealed, the Vault Root Key and derived material dwell in
process memory. An unattended unsealed agent on a shared workstation expands the
window for same-UID compromise and physical access. Operators need automatic
re-seal after inactivity without requiring a separate client to call `seal`.

ADR-0002 names an "idle-trigger" background worker but does not define the
timeout source, what counts as activity, or middleware ordering relative to
peer-credential authentication. ADR-0010's anacron "idle" windows for backups
are a different concept and must not be conflated with vault idle re-lock.

## Decision Drivers

* Limit VRK dwell after the operator walks away.
* Activity must not be refreshable by unauthenticated callers.
* Config override without forbidding a safe default.
* Distinct from backup scheduler idle logic (ADR-0010).
* Aligns with security profile guidance (ADR-0032) for recommended timeouts.

## Considered Options

1. **No automatic re-lock** — seal only via explicit CLI/MCP. Rejected for laptop
   and shared-user risk.
2. **Idle re-lock with activity touch only on mutating ops.** Rejected: long
   read sessions would still leave the vault unsealed after "use".
3. **Idle re-lock with post-peer-cred activity touch on every request + unseal.**
   Chosen.
4. **OS session lock hooks only.** Complementary later; not portable enough alone.

## Decision Outcome

Chosen option: "Option 3: Idle re-lock with post-peer-cred activity touch on
every request + unseal", because it bounds VRK dwell after walk-away while
preventing unauthenticated traffic from postponing re-lock.

### Supervisor

`bin/merkle-agent` spawns `idle_relock_task` while running:

* Polls `AppContext::last_activity`.
* When state is Unsealed and
  `now - last_activity >= idle_timeout`, executes `SealVaultCommand`.
* Sealed (or non-Unsealed) states skip idle seal.

### Timeout source

```text
idle_timeout = config.security.idle_lock_timeout_secs.map(Duration::from_secs)
            .unwrap_or(DEFAULT_IDLE_LOCK_TIMEOUT)
DEFAULT_IDLE_LOCK_TIMEOUT = 1800 seconds (30 minutes)
```

Config key: `[security] idle_lock_timeout_secs` (optional). When unset, **1800s**
applies regardless of security profile unless the composition root later wires
profile defaults (see ADR-0032 for recommended values).

### What counts as activity

1. **Companion Socket middleware** `touch_activity_middleware` runs **after**
   peer-credential authentication succeeds and refreshes `last_activity` for
   every authenticated request.
2. **Unseal** paths call `AppContext::touch_activity` on successful unseal so the
   idle clock starts from the unseal moment, not a stale pre-seal stamp.

### Load-bearing layer order

Router layers MUST place peer-cred **outside** (before) `touch_activity`. Touching
activity before auth would allow unauthenticated traffic to postpone re-lock.

### Non-goals

* Idle re-lock is not a substitute for OS screen lock or disk encryption.
* Backup anacron "idle" (ADR-0010) remains independent.
* MCP stdio processes do not own the timer; only agent-side activity matters.

### Consequences

* Good, because unsealed dwell is bounded without an explicit seal call.
* Good, because activity refresh requires successful peer-cred authentication.
* Bad, because pure-local work that never hits the socket still times out
  (by design).
* Bad, because the default 1800s may be too long for paranoid deployments —
  operators should set `idle_lock_timeout_secs` or follow ADR-0032 guidance
  (e.g. 300s).
* Neutral, because idle seal uses the normal `SealVaultCommand` audit path.

## Validation

* Unit/integration coverage of middleware order and timeout config parsing.
* Manual: unseal, wait past timeout with no requests, observe sealed status.

## More Information

* `bin/merkle-agent/src/background.rs` — `idle_relock_task`
* `bin/merkle-agent/src/run.rs` — `DEFAULT_IDLE_LOCK_TIMEOUT`
* `crates/merkle-adapter-companion-socket/src/router.rs` — middleware stack
* `crates/merkle-application/src/context.rs` — `touch_activity`
* ADR-0002, ADR-0010, ADR-0032
* `docs/arch/operations/lifecycle.md`
