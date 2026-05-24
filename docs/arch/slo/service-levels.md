# Merkle Service Level Objectives

## Overview

This document defines Service Level Indicators (SLIs) and Service Level
Objectives (SLOs) for the Merkle vault agent running on a single user host.
Its purpose is to establish measurable reliability targets, derive error
budgets, and provide the basis for operational review and incident response.

Scope: the Vault Agent daemon process and the MCP Adapter it hosts, as
experienced by an authorized MCP session or Companion Socket caller when the
host is running and the agent process is active. Host availability, network
availability, and all external service availability are explicitly excluded.

## Service Boundary

**The service** is the Vault Agent process (`merkle agent`) and the MCP Server
processes it supports. The service is considered available when the agent
process is healthy and the Companion Socket is accepting connections.

The measurement window for availability, latency, and socket SLIs is
**agent-up time only**: intervals where the host is powered off, sleeping,
hibernating, or the agent has not been started are excluded from both
numerator and denominator. This exclusion is explicit and non-negotiable —
the agent cannot be held accountable for host lifecycle events.

Two operational windows are distinguished:

| Window type | Definition |
|---|---|
| agent-up | Host is running, agent process is in the Unsealed or Sealed state, accepting requests |
| host-up | Host is on, irrespective of agent state — used for backup freshness only |

## Service Level Indicators

### Availability of vault.list, vault.use, vault.reveal

Measured as the ratio of successful MCP tool responses (HTTP 200-equivalent,
non-error JSON-RPC result) to total requests received, over a 30-day rolling
window, agent-up only. A response that returns a structured error (e.g.,
`permission_denied`) still counts as a successful response at the transport
layer; only internal panics, timeouts, and process crashes count as failures.

**Source:** agent metrics endpoint (`/metrics`, Prometheus exposition format),
counter pair `merkle_rpc_requests_total` and `merkle_rpc_errors_total`.

### Latency (p50 / p95 / p99) per operation class

Measured from the moment the MCP Adapter receives a complete tool-call frame
to the moment it writes the last byte of the response frame. External-service
round-trips (SSH handshake, HTTP round-trip, OOB Confirmation wait) are
subtracted from the measurement window for proxy tools.

**Source:** histogram `merkle_rpc_duration_seconds` labeled by `op`.

### Data Durability

Whether the committed-write durability invariants hold after process
termination. Measured separately for two failure modes:

- **Graceful shutdown:** `SIGTERM` received, agent drains in-flight writes and
  exits. Target: zero loss.
- **Crash (SIGKILL or panic):** agent dies without a drain phase. Loss bound
  comes from the WAL fsync policy; the target is that no more than the last 10
  mutations committed since the most recent SQLite checkpoint are at risk.

The indicator is NOT an availability ratio. It is a binary pass/fail
property evaluated by the WAL configuration audit and periodic durability
probe. A result of 0 (invariant violated) constitutes an immediate SLO
breach regardless of the measurement window.

**Source:** `merkle_durability_invariants_ok` gauge (new metric, declared in
`../operations/observability.md`), emitted by `merkle doctor --durability`
audits. A gauge value of 0 is a breach. WAL configuration audit confirms
fsync and checkpoint settings at startup.

### Audit Chain Integrity

Continuous verifiability of the Merkle-style hash chain. The chain is
considered intact when the Chain Verifier traverses every Audit Entry without
encountering a `broken_at_entry` condition or an `hmac_mismatch`. Integrity
is a binary property: either 100% of entries are verifiable or the SLO is
breached.

**Source:** `merkle doctor --chain` exit code; continuous background verifier
emitting `merkle_chain_integrity_ok` gauge (1 = intact, 0 = broken).

### Backup Freshness (RPO)

At any point in host-up time, the elapsed time since the last successful
Backup. Triggered by the Anacron Trigger, Change-Triggered Backup, and Sleep
Hook.

**Source:** `merkle_backup_last_success_timestamp_seconds` gauge; evaluated
continuously against the configured `max_interval`.

### Restore Time (RTO)

Elapsed wall-clock time from the moment `merkle restore` begins reading the
backup archive to the moment the vault is accessible. Measured per restore
attempt.

**Source:** histogram `merkle_restore_duration_seconds_bucket` (new metric,
declared in `../operations/observability.md`). The p99 of this histogram
over a 30-day window must remain below 60 s for a vault of fewer than
1,000 secrets on local NVMe storage.

### Restore Success Rate

Ratio of successful restores (process exits 0, vault is accessible after
restore) to attempted restores over a 30-day rolling window.

**Source:** CLI exit code captured in structured log; `merkle_restore_total`
counter labeled `outcome={success,corrupt_backup,error}`.

### Unseal Success Rate

Ratio of successful Unseal Protocol completions to attempted unseals over a
30-day rolling window, counted only when the OS Keychain entry or a
passphrase is present and accessible. Failures due to missing or revoked
keychain entries are excluded from the denominator.

**Source:** `merkle_unseal_total` counter labeled `outcome` and `reason`.

### Companion Socket Connect Success Rate

Ratio of successful Unix domain socket connection handshakes from authorized
peer processes to attempted connections, over a 30-day rolling window,
agent-up only. Authorization failures (unknown PID, blocked consumer) count
as neither success nor failure — they are tracked separately as policy events.

**Source:** `merkle_companion_socket_connects_total` labeled
`outcome={accepted,rejected}`.

## Service Level Objectives

| SLI | Target | Window | Notes |
|---|---|---|---|
| Agent availability | 99.5% | 30d rolling | agent-up only; excludes host-sleep and cold start |
| vault.list p95 latency | < 50 ms | 30d rolling | 1,000 secrets in namespace, FTS5 index warm |
| vault.use p95 latency | < 100 ms | 30d rolling | issuance + Audit Entry write; excludes OOB wait |
| vault.reveal p95 latency | < 200 ms | 30d rolling | excludes OOB Confirmation round-trip |
| vault.ssh.exec overhead p95 | < 50 ms | 30d rolling | agent overhead only; excludes remote command time |
| Data durability — graceful shutdown | zero loss | always | WAL drain completed before process exit |
| Data durability — crash | loss bounded to last 10 mutations | always | WAL fsync policy and checkpoint frequency |
| Audit chain integrity | 100% verifiable | always | breach triggers immediate alert and freeze |
| Backup freshness (RPO) | max(24h, 10 mutations) | host-up | Anacron + change-triggered + sleep-hook |
| Restore time (RTO) | < 60 s | per restore | vault < 1,000 secrets on local NVMe |
| Restore success rate | 99.0% | 30d rolling | excludes corrupt backup files |
| Unseal success rate | 99.9% | 30d rolling | keychain or passphrase present |
| Companion Socket connect success rate | 99.9% | 30d rolling | authorized peer; policy-denied excluded |

## Error Budgets

Error budgets translate the percentage targets above into allowable failure
time or failure counts over the measurement window. The budget governs the
pace of risky changes: when the budget is consumed, reliability work takes
priority over feature development.

**Agent availability — 99.5% over 30 days**

30 days = 43,200 agent-up minutes (upper bound).
0.5% budget = 216 minutes = 3 hours 36 minutes of allowed downtime per month.
At a burn rate of 1x the budget depletes in 30 days. Sustained burn rate of
6x (approximately 43 minutes of downtime per day) depletes the budget in
5 days and triggers an immediate reliability review.

**vault.use p95 latency**

Latency SLOs do not translate directly into time budgets. Instead, the error
budget is expressed as: no more than 5% of vault.use calls may exceed 100 ms
p95 in any 30-day window. A rolling 1-hour window exceeding 10% slow
requests constitutes a fast-burn alert.

**Unseal success rate — 99.9% over 30 days**

Assuming a typical user performs 2 unseals per day: 60 unseal attempts per
month. 0.1% budget = 0.06 failures, rounded to 1 tolerated failure per
month. A second failure in the same calendar month triggers root cause
analysis.

**Audit chain integrity — 100%**

No error budget. Any verifier failure is a P1 incident with immediate
operational freeze on Secret writes until the chain is repaired or attested.

**Backup freshness — max(24h, 10 mutations)**

The budget is measured as the fraction of host-up time during which the RPO
target is exceeded. Target: 0% of host-up time spent outside RPO. A single
RPO violation lasting more than 2 hours triggers a postmortem.

## Out-of-Scope

The following are explicitly excluded from Merkle SLOs:

- Host availability: laptop powered off, sleeping, hibernating, or kernel
  panicked. The agent cannot be online when the host is not.
- Network availability: connectivity required for remote audit webhook sync,
  SSH targets, or HTTP endpoints.
- External service availability: SSH target hosts, HTTP API endpoints, drive
  sync services (iCloud Drive, Google Drive, Dropbox).
- LLM client behavior: Claude Code window crashes, MCP session drops
  initiated by the client, or client-side timeout policies.
- Recovery Key handling: the operator's responsibility after the key is
  displayed at `merkle init`. Safe storage and retrieval are out of scope.
- Drive sync conflict resolution: delegated entirely to the host's drive
  client. Merkle writes backup files atomically; conflict resolution after
  that is the drive client's concern.
- OS Keychain availability: if the OS Keychain service is unavailable (e.g.,
  locked screen requiring re-authentication in sandboxed environments),
  Unseal failures caused by this condition are excluded from the Unseal
  success rate denominator.

## Measurement Plan

| SLI | Collection method | Tool |
|---|---|---|
| Agent availability | Prometheus counter ratio scrape from `/metrics` (`merkle_rpc_requests_total` / `merkle_rpc_errors_total`) | `merkle agent --metrics-port 9117` |
| Latency (all ops) | Histogram from metrics endpoint (`merkle_rpc_duration_seconds_bucket`), labeled by `op` | Grafana Mimir or local `promtool` |
| Data durability | `merkle_durability_invariants_ok` gauge; breach on value = 0 | `merkle doctor --durability` |
| Audit chain integrity | `merkle_chain_integrity_ok` gauge + `merkle doctor --chain` | Automated; alert on gauge = 0 |
| Backup freshness | `merkle_backup_age_seconds` gauge compared to `now()` and mutation counter | `merkle doctor --backup` |
| Restore time (RTO) | `merkle_restore_duration_seconds_bucket` histogram p99 | Metrics endpoint |
| Restore success rate | `merkle_restore_total` counter labeled by `outcome`; CLI structured log exit code | `merkle restore --log-format json` |
| Unseal success rate | `merkle_unseal_total` counter labeled by `outcome` and reason | Metrics endpoint |
| Companion Socket connect rate | `merkle_companion_socket_connects_total` counter labeled by `outcome` | Metrics endpoint |

All metrics are local-only by default. When remote audit webhook sync is
enabled, aggregate SLI summaries are optionally forwarded as part of the
audit stream, but the primary measurement source remains the local agent.

## Review Cadence

**Quarterly SLO review:** Every three months, the operator reviews actual SLI
measurements against targets, adjusts targets if system characteristics have
changed, and updates error budget policy if warranted.

**Immediate review triggers:**
- Any breach of a zero-budget SLO (audit chain integrity, graceful durability).
- Error budget burn rate exceeding 6x for availability or latency.
- More than one Unseal failure in a calendar month.
- Any RPO violation lasting more than 2 hours.
- Any restore failure.

Postmortems follow the blameless model. Action items are tracked to closure
before the next quarterly review.

## Indicator-to-Metric Mapping

The following table cross-references every SLI defined in this document to
the exact Prometheus metric and query expression used to evaluate it. All
metrics are declared in `../operations/observability.md`.

| SLI | Metric(s) | PromQL expression (30d window) |
|---|---|---|
| Agent availability | `merkle_rpc_requests_total`, `merkle_rpc_errors_total` | `1 - (sum(increase(merkle_rpc_errors_total[30d])) / sum(increase(merkle_rpc_requests_total[30d])))` |
| vault.list p95 latency | `merkle_rpc_duration_seconds_bucket{op="vault.list"}` | `histogram_quantile(0.95, sum(rate(merkle_rpc_duration_seconds_bucket{op="vault.list"}[30d])) by (le))` |
| vault.use p95 latency | `merkle_rpc_duration_seconds_bucket{op="vault.use"}` | `histogram_quantile(0.95, sum(rate(merkle_rpc_duration_seconds_bucket{op="vault.use"}[30d])) by (le))` |
| vault.reveal p95 latency | `merkle_rpc_duration_seconds_bucket{op="vault.reveal"}` | `histogram_quantile(0.95, sum(rate(merkle_rpc_duration_seconds_bucket{op="vault.reveal"}[30d])) by (le))` |
| vault.ssh.exec overhead p95 | `merkle_rpc_duration_seconds_bucket{op="vault.ssh.exec"}` | `histogram_quantile(0.95, sum(rate(merkle_rpc_duration_seconds_bucket{op="vault.ssh.exec"}[30d])) by (le))` |
| Data durability — graceful shutdown | `merkle_durability_invariants_ok` | `min_over_time(merkle_durability_invariants_ok[30d]) == 1` |
| Data durability — crash | `merkle_durability_invariants_ok` | `min_over_time(merkle_durability_invariants_ok[30d]) == 1` |
| Audit chain integrity | `merkle_chain_integrity_ok` | `merkle_chain_integrity_ok == 1` |
| Backup freshness (RPO) | `merkle_backup_age_seconds` | `merkle_backup_age_seconds < 86400` |
| Restore time (RTO) | `merkle_restore_duration_seconds_bucket` | `histogram_quantile(0.99, sum(rate(merkle_restore_duration_seconds_bucket[30d])) by (le)) < 60` |
| Restore success rate | `merkle_restore_total` | `sum(increase(merkle_restore_total{outcome="success"}[30d])) / sum(increase(merkle_restore_total[30d]))` |
| Unseal success rate | `merkle_unseal_total` | `sum(increase(merkle_unseal_total{outcome="success"}[30d])) / sum(increase(merkle_unseal_total[30d]))` |
| Companion Socket connect success rate | `merkle_companion_socket_connects_total` | `sum(increase(merkle_companion_socket_connects_total{outcome="accepted"}[30d])) / sum(increase(merkle_companion_socket_connects_total[30d]))` |

## References

- ADR-0009: Merkle-style audit hash chain
- ADR-0010: Anacron-style backup triggers
- Doctor command: `merkle doctor`
- Operations observability guide: `../operations/observability.md`
- Glossary: `../glossary.md`
