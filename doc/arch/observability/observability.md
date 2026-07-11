# Observability Strategy — Merkle

## Goals

Operators and automated health checks must answer: is the agent up, is the vault
sealed or unsealed, is the audit chain intact, are backups fresh, and are
latency SLOs for list/reveal/use/proxy within budget — without exposing secret
plaintext in logs or metrics labels.

## Signals

| Signal class | Mechanism | Notes |
|---|---|---|
| Metrics | Prometheus text exposition | Optional metrics bind; non-loopback requires auth_token |
| Logs | Structured JSON | stdout (TTY), state log file (service), MCP stderr |
| Audit chain | SQLite hash chain + doctor | Not a metrics substitute for integrity |
| Traces | Not required for v0.2 | Future OTLP optional; do not emit secret plaintext |

Canonical ops narrative: docs/arch/operations/observability.md.

## Metrics conventions

* Prefix: merkle_
* Outcomes labeled allow / deny / error on RPC counters
* Never label secret material, passphrases, or recovery keys
* Representative series: merkle_rpc_requests_total, merkle_rpc_duration_seconds_*

## Tracing

Distributed tracing is not required. Local correlation uses structured log
fields (session_id, namespace_id, operation name) and audit sequence numbers.
A future OTLP exporter must not emit secret plaintext as span attributes.

## Cardinality

| Label | Bounded Value Set | Signal |
|---|---|---|
| op | Closed set of RPC operation names | merkle_rpc_requests_total |
| outcome | allow, deny, error | merkle_rpc_requests_total |
| error_type | Closed adapter error classes | merkle_rpc_errors_total |
| le | Histogram bucket bounds | merkle_rpc_duration_seconds_bucket |

Do not use free-form handles or arbitrary proxy hostnames as metric labels.

## Logs

* Levels: TRACE DEBUG INFO WARN ERROR
* Redact secrets; log handles and public metadata only

## Doctor

GET /v1/agent/doctor, merkle doctor, and vault_doctor aggregate sealed-safe checks.

## Observability requirements for new features

Every feature that adds an operator-visible path MUST document audit op (if any),
metrics (if any), doctor impact (if any), and safe log fields.
