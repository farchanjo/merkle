# Service-Level Objectives — Merkle

## Purpose

Service-level objectives for the Merkle vault agent, companion socket, and MCP
adapter. Indicator and objective YAML files live under this directory tree.

## Scope

Applies to local-first single-operator deployments and CI dogfood agents. Multi-
tenant SaaS is out of scope.

## Services

| Service | Definition | Descriptor |
|---|---|---|
| vault-agent | Long-running merkle-agent daemon | `services/vault-agent.yaml` |
| companion-socket | HTTP/1.1 over Unix domain socket | `services/companion-socket.yaml` |
| mcp-adapter | merkle-mcp stdio process | `services/mcp-adapter.yaml` |

## Indicators

| Indicator file | Measures |
|---|---|
| `indicators/agent-availability.yaml` | Agent up / socket accept |
| `indicators/unseal-success-rate.yaml` | Unseal ceremony success |
| `indicators/audit-chain-integrity.yaml` | Chain verify outcomes |
| `indicators/companion-socket-connect-rate.yaml` | Client connect success |
| `indicators/vault-list-latency-p95.yaml` | List latency |
| `indicators/vault-reveal-latency-p95.yaml` | Reveal latency |
| `indicators/vault-use-latency-p95.yaml` | Use-token latency |
| `indicators/vault-ssh-exec-overhead-p95.yaml` | SSH proxy overhead |
| `indicators/backup-freshness-rpo.yaml` | Backup age vs RPO |
| `indicators/restore-rto.yaml` | Restore duration |
| `indicators/restore-success-rate.yaml` | Restore success |
| `indicators/durability-invariants-ok.yaml` | Durability checks |
| `indicators/vault-audit-query-availability.yaml` | Audit query serve rate |

## Objectives

Each objective YAML under `objectives/` binds an indicator to a target window
(for example availability ratio or latency percentile). Alert policies under
`alerting/` attach multi-window burn alerts where defined.

## Objectives catalog

| Objective | Indicator intent |
|---|---|
| slo-agent-availability | Agent remains reachable |
| slo-unseal-success-rate | Unseal succeeds for valid operators |
| slo-audit-chain-integrity | Chain verification remains healthy |
| slo-companion-socket-connect-rate | Socket connects succeed |
| slo-vault-list-latency-p95 | List stays interactive |
| slo-vault-reveal-latency-p95 | Reveal path bounded |
| slo-vault-use-latency-p95 | Use path bounded |
| slo-vault-ssh-exec-overhead-p95 | Proxy overhead bounded |
| slo-backup-freshness-rpo | Backups meet RPO |
| slo-restore-rto | Restores meet RTO |
| slo-restore-success-rate | Restores succeed |
| slo-durability-graceful | Graceful shutdown durability |
| slo-durability-crash | Crash durability |
| slo-vault-audit-query-availability | Audit query available |

## Error budget

* Prefer fail-closed security over burning budget on open SSRF or auth holes.
* Idle re-lock seals are not availability errors for the sealed state.
* Rebaseline-related doctor notes are operator-managed (ADR-0029).

## Measurement

Local Prometheus scrape when metrics are enabled. Datasource:
`datasources/local-metrics.yaml`. Field catalog in
`operations/observability.md`.

## Alerting

Alert conditions under `alerting/` cover fast-burn availability, latency, audit
chain broken, backup overdue, OOB notifier down, and unseal failure.

## Review cadence

Review objectives when shipping ADR-level transport or crypto changes, or when
dogfood metrics show sustained budget burn.

## Related

* `service-levels.md` narrative
* ADR-0010 backups, ADR-0009 audit, ADR-0030 SSRF, ADR-0031 idle
