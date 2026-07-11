# Observability Strategy — Merkle

## Goals

Operators and automated health checks must answer: is the agent up, is the vault
sealed or unsealed, is the audit chain intact, are backups fresh, and are
latency SLOs for list/reveal/use/proxy within budget — without exposing secret
plaintext in logs or metrics labels.

## Signals

| Signal class | Mechanism | Notes |
|---|---|---|
| Metrics | Prometheus text exposition | Optional `[metrics]` bind; non-loopback requires `auth_token` |
| Logs | Structured JSON | stdout (TTY), state log file (service), MCP stderr |
| Audit chain | SQLite hash chain + doctor | Not a metrics substitute for integrity |
| Traces | Not required for v0.2 | Future OTLP optional; do not block on distributed tracing |

Canonical ops narrative: `docs/arch/operations/observability.md` (symlinked as
`doc/arch/operations/observability.md`).

## Metrics conventions

* Prefix: `merkle_`
* Outcomes labeled `allow` / `deny` / `error` on RPC counters
* Never label secret handles' private material, passphrases, or recovery keys
* Representative series: `merkle_rpc_requests_total`,
  `merkle_rpc_duration_seconds_*`, process metrics when the endpoint is enabled

SLO indicators live under `docs/arch/slo/` (availability, unseal success, audit
integrity, list/reveal/use latency, backup RPO, restore RTO).

## Tracing

Distributed tracing is **not required** for the current product surface. Local
correlation uses structured log fields (`session_id`, `namespace_id`, operation
name) and audit entry sequence numbers. A future OTLP exporter is optional and
must not emit secret plaintext or recovery material as span attributes.

## Cardinality

| Label | Bounded Value Set | Signal |
|---|---|---|
| `op` | Closed set of RPC / tool operation names | `merkle_rpc_requests_total`, duration histograms |
| `outcome` | `allow`, `deny`, `error` | `merkle_rpc_requests_total` |
| `error_type` | Closed adapter/application error classes | `merkle_rpc_errors_total` |
| `le` | Histogram bucket bounds | `merkle_rpc_duration_seconds_bucket` |

Do not use free-form handles, arbitrary proxy hostnames, or full peer paths as
metric labels. Doctor checks are pull-based and do not create unbounded series.

## Logs

* Levels: TRACE/DEBUG/INFO/WARN/ERROR as in ops observability doc
* Redact secrets; log handles and public metadata only
* LaunchAgent: `~/Library/Logs/merkle-agent.{out,err}.log` on macOS

## Doctor

`GET /v1/agent/doctor` / `merkle doctor` / `vault_doctor` aggregates sealed-safe
checks (vault state, audit integrity when unsealed, storage, OOB notifier,
FTS5, keystore backend visibility). Prefer doctor for integrity questions;
prefer Prometheus for continuous latency/availability.

## Observability requirements for new features

Every feature that adds an operator-visible path MUST document:

1. Audit `AuditOp` (if any)
2. Metrics counters/histograms (if any)
3. Doctor check impact (if any)
4. Log fields that are safe to emit
