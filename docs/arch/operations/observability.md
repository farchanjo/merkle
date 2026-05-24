# Observability

Logging, metrics, audit log access, and the doctor command for Merkle.

## 1. Logging

### Destinations

| Condition | Destination |
|---|---|
| Running attached to a TTY (development, manual start) | Structured JSON to `stdout` |
| Running as a service (launchd, systemd, SCM) | Structured JSON to `~/.local/state/merkle/agent.log` |
| MCP Adapter process | Structured JSON to `stderr` (captured by Claude Code) |

The log file is rotated when it reaches 50 MB. Up to five rotated files
are retained. The log directory is created on first write if absent.

On Windows, the log path is
`%LOCALAPPDATA%\merkle\logs\agent.log`.

### Format

Each log line is a single JSON object terminated by a newline. Fields:

```json
{
  "ts": "2026-05-22T10:00:00.123456Z",
  "level": "INFO",
  "target": "merkle::agent::backup",
  "msg": "backup completed",
  "session_id": "01JVXG...",
  "namespace_id": "01JVXH...",
  "elapsed_ms": 412
}
```

Fields beyond `ts`, `level`, `target`, and `msg` are context-specific
structured fields added by the emitting module.

### Log Levels

| Level | When used |
|---|---|
| `TRACE` | Fine-grained internal state; byte-level crypto operations; not suitable for production |
| `DEBUG` | Decision points, branch selections, per-call durations |
| `INFO` | Lifecycle events: start, seal, unseal, backup complete, migration applied |
| `WARN` | Recoverable anomalies: backup target unreachable, chain verification warning, re-lock on error |
| `ERROR` | Unrecoverable errors that cause a request to fail or the process to exit |

### Environment Variables

| Variable | Effect |
|---|---|
| `RUST_LOG` | Standard `tracing` / `env_logger` directive syntax. Example: `merkle=debug,sqlx=warn` |
| `MERKLE_LOG` | Alias for `RUST_LOG` scoped to Merkle targets. Takes precedence over `RUST_LOG` when both are set. |
| `MERKLE_LOG_FILE` | Override the log file path. Useful in containers or shared systems. |
| `MERKLE_LOG_FORMAT` | `json` (default) or `pretty` (human-readable; intended for development only) |

### Per-module Filtering Examples

```sh
# Show all Merkle logs at DEBUG; suppress SQLx query logs
RUST_LOG=merkle=debug,sqlx=warn merkle agent

# Show only backup and audit modules at TRACE
RUST_LOG=merkle::backup=trace,merkle::audit=trace merkle agent

# Suppress everything except errors
RUST_LOG=error merkle agent
```

### Privacy Constraints

The logger MUST NOT emit:

- The `private_blob` field or any decrypted Secret material.
- Revealed plaintext in any log level, including TRACE.
- Full Handle paths in DEBUG if the Namespace label contains PII
  (operators may configure `mask_handle_in_debug = true` in
  `config.toml` to replace the Namespace label with its UUIDv7).
- Master Key, Vault Root Key, or Namespace DEK bytes.
- Use Token values.

These constraints are enforced by wrapper types (`Redacted<T>`) that
implement `Debug` as `[REDACTED]` and `Display` as `[REDACTED]`.

---

## 2. Metrics

The agent exposes a Prometheus-compatible `/metrics` endpoint on a
localhost-only HTTP port when metrics are enabled.

### Configuration

```toml
[metrics]
enabled = true
port    = 9117          # default; localhost only
```

The endpoint listens on `127.0.0.1:<port>` only. It is never exposed on
any network interface other than the loopback. No authentication is
required on the loopback port; access control is enforced by the OS
(only processes on the same host can reach it).

### Core Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `merkle_secrets_total` | Gauge | `namespace`, `category` | Count of live Secrets per Namespace and Category |
| `merkle_audit_entries_total` | Counter | — | Cumulative count of Audit Entries written since agent start |
| `merkle_use_tokens_issued_total` | Counter | — | Cumulative Use Tokens issued |
| `merkle_use_tokens_consumed_total` | Counter | — | Cumulative Use Tokens resolved via the Companion Socket |
| `merkle_use_tokens_expired_total` | Counter | — | Use Tokens that expired without being consumed |
| `merkle_reveals_total` | Counter | `sensitivity`, `outcome` | Reveal operations; `outcome` is `allowed`, `denied`, or `error` |
| `merkle_backup_age_seconds` | Gauge | — | Seconds since the last successful backup |
| `merkle_chain_verifications_total` | Counter | `outcome` | Chain verifications run; `outcome` is `ok` or `broken` |
| `merkle_rate_limit_denials_total` | Counter | `class` | Rate limit rejections per class (`plaintext_reads`, `use_token_resolves`, `reveals`) |
| `merkle_companion_socket_connects_total` | Counter | `outcome` | Companion Socket connection attempts; `outcome` is `accepted` or `rejected`. Emitted by `companion_socket::listener`. |
| `merkle_chain_integrity_ok` | Gauge | — | 1 if last chain verification passed, 0 if broken or unknown. Emitted by `crypto::chain_verifier` after each background pass. |
| `merkle_rpc_requests_total` | Counter | `op`, `outcome` | Total RPC requests by operation and outcome (`allow`, `deny`, `error`). Emitted by `mcp_adapter::interceptor::rpc_metrics`. |
| `merkle_rpc_errors_total` | Counter | `op`, `error_type` | RPC errors broken down by operation and error type. Emitted by `mcp_adapter::interceptor::rpc_metrics`. |
| `merkle_rpc_duration_seconds_bucket` | Histogram | `op`, `le` | RPC duration histogram per operation. Emitted by `mcp_adapter::interceptor::rpc_metrics`. |
| `merkle_rpc_duration_seconds_count` | Histogram-derived | `op` | Total histogram observations per operation. Emitted by `mcp_adapter::interceptor::rpc_metrics`. |
| `merkle_restore_total` | Counter | `outcome` | Restore operations by outcome (`success`, `corrupt_backup`, `error`). Emitted by `backup::restore`. |
| `merkle_unseal_total` | Counter | `outcome` | Unseal attempts by outcome (`success`, `failure`, `locked_out`). Emitted by `identity::unseal`. |
| `merkle_restore_duration_seconds_bucket` | Histogram | `le` | Restore operation duration histogram. Emitted by `backup::restore`. SLI source for the Restore RTO < 60 s objective. |
| `merkle_durability_invariants_ok` | Gauge | — | 1 if all WAL durability invariants passed, 0 if any invariant failed. Emitted by `merkle doctor --durability` audits. |
| `merkle_oob_notifier_available` | Gauge | — | 1 if the OOB Notifier is reachable and healthy, 0 if down. Emitted by the OOB Notifier health probe. |

All counters are reset to zero on agent restart. Gauges reflect live
state.

> **Note:** `merkle_companion_socket_connects_total` uses `outcome`
> labels `accepted` and `rejected`. Do not use the legacy name
> `merkle_companion_connects_total` — it is not emitted by the agent.

### Scrape Example

```sh
curl -s http://localhost:9117/metrics | grep merkle_
```

The endpoint also exposes standard Go-style process metrics
(`process_cpu_seconds_total`, `process_resident_memory_bytes`) via the
Prometheus Rust client library.

---

## 3. Audit Log Access

The audit log is an append-only hash chain stored in the SQLite database.
It records every Secret operation with full provenance.

### CLI: merkle audit query

```sh
# All reveal operations in the last 24 hours
merkle audit query --since 24h --op reveal

# All operations in the acme-prod namespace since a specific timestamp
merkle audit query \
    --since 2026-05-01T00:00:00Z \
    --namespace acme-prod

# High-sensitivity reveals only
merkle audit query --op reveal --sensitivity high

# Exports in NDJSON for pipeline consumption
merkle audit query --since 7d --format ndjson > audit-week.ndjson
```

Available flags:

| Flag | Description |
|---|---|
| `--since <duration|timestamp>` | Start of the query window (e.g., `24h`, `2026-05-01T00:00:00Z`) |
| `--until <duration|timestamp>` | End of the query window (default: now) |
| `--op <op>` | Filter by operation type: `unseal`, `put`, `get`, `use`, `reveal`, `rotate`, `delete`, `restore` |
| `--namespace <label>` | Filter by Namespace label |
| `--sensitivity <level>` | Filter by Secret Sensitivity: `low`, `medium`, `high` |
| `--format <fmt>` | Output format: `text` (default), `json`, `ndjson` |
| `--limit <n>` | Maximum rows returned (default: 500) |
| `--verify-chain` | Run Chain Verifier before returning results; exit non-zero if chain is broken |

### MCP Tool: vault.audit.query

The same query capabilities are available through the MCP tool
`vault.audit.query`. Parameters mirror the CLI flags:

```json
{
  "since": "24h",
  "op": "reveal",
  "namespace": "acme-prod",
  "format": "json"
}
```

The MCP tool returns results as a JSON array of Audit Entry objects. It
is intended for LLM-driven audit review within a Claude Code session,
not for bulk export (use the CLI for large windows).

### Output Fields (per entry)

| Field | Description |
|---|---|
| `ts` | ISO 8601 UTC timestamp |
| `entry_id` | UUIDv7 of the Audit Entry |
| `session_id` | MCP Session that triggered the operation |
| `namespace_id` | UUIDv7 of the Namespace |
| `op` | Operation type |
| `handle` | Opaque Handle of the Secret |
| `purpose` | Free-text purpose string provided by the caller |
| `outcome` | `ok`, `denied`, or `error` |
| `caller_pid` | PID of the caller process |
| `current_hash` | BLAKE3 hash of this entry (used by Chain Verifier) |
| `prev_hash` | `current_hash` of the previous entry |

---

## 4. Doctor Command

`merkle doctor` runs a suite of diagnostic checks and prints a structured
report. It is intended for operator troubleshooting and automated health
probes.

```sh
merkle doctor
merkle doctor --json          # machine-readable output
merkle doctor --fix           # attempt auto-fix for fixable issues
```

### Output Sections

| Section | Check | Auto-fix |
|---|---|---|
| Agent status | Confirm the agent process is reachable via the Companion Socket | No |
| Database integrity | Run `PRAGMA integrity_check` on the SQLite database | No |
| Keychain access | Attempt to read the Master Key entry from the OS keychain (read-only probe) | No |
| Audit chain | Run the Chain Verifier end-to-end; report `ok` or `broken` with the first broken entry ID | No |
| Last backup age | Report seconds since last successful backup; warn if `> max_interval * 0.8`; error if `> max_interval` | Yes: trigger an immediate backup if age is excessive and target is reachable |
| Expiring secrets | List Secrets with an `expires_at` in the next 7 days | No |
| Disk space | Report free space on the filesystem hosting the database; warn if `< 100 MB`, error if `< 10 MB` | No |

Example output (text format):

```
Merkle doctor — 2026-05-22T10:00:00Z

[OK] Agent status      running (pid 12345)
[OK] Database          integrity check passed
[OK] Keychain          master-v1 accessible
[OK] Audit chain       5423 entries verified, chain intact
[WARN] Last backup     36h ago (max_interval=24h) — auto-fixing
  --> Triggering backup to ~/Backups/merkle ...
  --> Backup complete (2.1 MB, 412ms)
[OK] Expiring secrets  none in next 7 days
[OK] Disk space        42.3 GB free
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | All checks passed (warnings do not affect exit code) |
| 1 | One or more checks returned `ERROR` status |
| 2 | Agent is unreachable (socket not found) |

---

## 5. Alerting Suggestions

For operators running a local Prometheus + Alertmanager stack, the
following alert rules are recommended. These are example configurations
and are not automatically deployed by Merkle.

### Alertmanager rules example

```yaml
groups:
  - name: merkle
    rules:
      - alert: MerkleAuditChainBroken
        expr: increase(merkle_chain_verifications_total{outcome="broken"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Merkle audit chain integrity failure"
          description: >
            The audit hash chain has reported a broken link. This indicates
            possible tampering or disk corruption. Investigate immediately.

      - alert: MerkleBackupOverdue
        expr: merkle_backup_age_seconds > 86400
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Merkle backup is overdue"
          description: >
            No successful backup has completed in the last 24 hours.
            Check the backup target availability and run `merkle backup`.

      - alert: MerkleRateLimitBurst
        expr: increase(merkle_rate_limit_denials_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Merkle rate limit denials are elevated"
          description: >
            More than 10 rate-limit denials in 5 minutes. This may indicate
            an automated tool calling reveal or use_token in a tight loop,
            or a misconfigured policy.
```

Additional alerts to consider:

- `merkle_reveals_total{outcome="denied"}` spike may indicate a
  misconfigured Reveal Policy.
- `merkle_companion_socket_connects_total{outcome="rejected"}` spike may
  indicate a process not in the `allowed_consumers` list attempting access.
- `merkle_backup_age_seconds` approaching `max_interval` warrants a
  warning at 80% of the interval.

---

## 6. Indicator Contract

Every metric listed in the Core Metrics catalog above is part of the
agent's external contract. The following rules govern its lifecycle:

- **Removal or renaming** of any catalogued metric requires an
  Architecture Decision Record (ADR). Existing SLO YAML files,
  runbooks, dashboards, and alert rules reference these names by
  string — a silent rename is a breaking change.
- **Adding new metrics** requires updating this catalog (name, type,
  labels, description, and emission point) before referencing the
  metric in any SLO YAML, runbook, alert rule, or dashboard. The
  catalog is the source of truth; forward-references to undeclared
  metrics are not permitted.
- **Label additions** to an existing metric are non-breaking but must
  still be documented here. Label removals are breaking and require an
  ADR.
- **Emission point changes** (moving a metric from one Rust module to
  another) are non-breaking at the wire level but must be updated in
  this table to keep the catalog accurate.

---

## 7. Privacy in Logs

The following rules are non-negotiable and enforced at the type level:

**Never logged at any level:**

- `private_blob` content or any decrypted form of a Secret's sensitive
  material.
- Plaintext returned by a Reveal operation.
- Master Key, Vault Root Key, Namespace DEK, or Use Token bytes.
- Recovery Key material.

**Conditionally masked (DEBUG and below):**

- Handle path components containing the Namespace label may be masked
  to the Namespace UUIDv7 when `mask_handle_in_debug = true` is set in
  `config.toml`. This is useful when Namespace labels contain project
  names or environment identifiers that an operator considers sensitive
  in debug output.

**Always safe to log:**

- Handle paths when `mask_handle_in_debug = false` (default): they
  contain no plaintext Secret material.
- Audit Entry chain hashes, entry IDs, and timestamps.
- Operation outcomes (`ok`, `denied`, `error`).
- Metric counter increments.
- Elapsed durations and byte counts.

**Testing.** The Merkle test suite includes a log scrubber assertion that
fails any test that emits a log line containing patterns matching known
key material. This is enforced in CI.
