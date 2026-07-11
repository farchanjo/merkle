# Service-Level Objectives — Merkle

## Purpose

Service-level objectives for the Merkle vault agent, companion socket, and MCP adapter.

## Scope

Local-first single-operator deployments and CI dogfood agents.

## Services

| Service | Descriptor |
|---|---|
| vault-agent | [services/vault-agent.yaml](services/vault-agent.yaml) |
| companion-socket | [services/companion-socket.yaml](services/companion-socket.yaml) |
| mcp-adapter | [services/mcp-adapter.yaml](services/mcp-adapter.yaml) |

## Indicators

- [indicators/agent-availability.yaml](indicators/agent-availability.yaml)
- [indicators/audit-chain-integrity.yaml](indicators/audit-chain-integrity.yaml)
- [indicators/backup-freshness-rpo.yaml](indicators/backup-freshness-rpo.yaml)
- [indicators/companion-socket-connect-rate.yaml](indicators/companion-socket-connect-rate.yaml)
- [indicators/durability-invariants-ok.yaml](indicators/durability-invariants-ok.yaml)
- [indicators/restore-rto.yaml](indicators/restore-rto.yaml)
- [indicators/restore-success-rate.yaml](indicators/restore-success-rate.yaml)
- [indicators/unseal-success-rate.yaml](indicators/unseal-success-rate.yaml)
- [indicators/vault-audit-query-availability.yaml](indicators/vault-audit-query-availability.yaml)
- [indicators/vault-list-latency-p95.yaml](indicators/vault-list-latency-p95.yaml)
- [indicators/vault-reveal-latency-p95.yaml](indicators/vault-reveal-latency-p95.yaml)
- [indicators/vault-ssh-exec-overhead-p95.yaml](indicators/vault-ssh-exec-overhead-p95.yaml)
- [indicators/vault-use-latency-p95.yaml](indicators/vault-use-latency-p95.yaml)

## Objectives

- [objectives/slo-agent-availability.yaml](objectives/slo-agent-availability.yaml)
- [objectives/slo-audit-chain-integrity.yaml](objectives/slo-audit-chain-integrity.yaml)
- [objectives/slo-backup-freshness-rpo.yaml](objectives/slo-backup-freshness-rpo.yaml)
- [objectives/slo-companion-socket-connect-rate.yaml](objectives/slo-companion-socket-connect-rate.yaml)
- [objectives/slo-durability-crash.yaml](objectives/slo-durability-crash.yaml)
- [objectives/slo-durability-graceful.yaml](objectives/slo-durability-graceful.yaml)
- [objectives/slo-restore-rto.yaml](objectives/slo-restore-rto.yaml)
- [objectives/slo-restore-success-rate.yaml](objectives/slo-restore-success-rate.yaml)
- [objectives/slo-unseal-success-rate.yaml](objectives/slo-unseal-success-rate.yaml)
- [objectives/slo-vault-audit-query-availability.yaml](objectives/slo-vault-audit-query-availability.yaml)
- [objectives/slo-vault-list-latency-p95.yaml](objectives/slo-vault-list-latency-p95.yaml)
- [objectives/slo-vault-reveal-latency-p95.yaml](objectives/slo-vault-reveal-latency-p95.yaml)
- [objectives/slo-vault-ssh-exec-overhead-p95.yaml](objectives/slo-vault-ssh-exec-overhead-p95.yaml)
- [objectives/slo-vault-use-latency-p95.yaml](objectives/slo-vault-use-latency-p95.yaml)

## SLO-agent-availability

Target: agent and socket remain reachable.
Indicator: [indicators/agent-availability.yaml](indicators/agent-availability.yaml)

## SLO-unseal-success-rate

Target: valid unseal ceremonies succeed.
Indicator: [indicators/unseal-success-rate.yaml](indicators/unseal-success-rate.yaml)

## SLO-audit-chain-integrity

Target: chain verification remains healthy when unsealed.
Indicator: [indicators/audit-chain-integrity.yaml](indicators/audit-chain-integrity.yaml)

## SLO-latency

- [indicators/vault-list-latency-p95.yaml](indicators/vault-list-latency-p95.yaml)
- [indicators/vault-reveal-latency-p95.yaml](indicators/vault-reveal-latency-p95.yaml)
- [indicators/vault-use-latency-p95.yaml](indicators/vault-use-latency-p95.yaml)
- [indicators/vault-ssh-exec-overhead-p95.yaml](indicators/vault-ssh-exec-overhead-p95.yaml)

## SLO-backup-and-restore

- [indicators/backup-freshness-rpo.yaml](indicators/backup-freshness-rpo.yaml)
- [indicators/restore-rto.yaml](indicators/restore-rto.yaml)
- [indicators/restore-success-rate.yaml](indicators/restore-success-rate.yaml)

## Error Budget Policy

Prefer fail-closed security over open SSRF or auth holes. Idle re-lock seals
are not availability errors. Rebaseline notes are operator-managed (ADR-0029).
Alerts live under [alerting/](alerting/).

## Measurement

Prometheus when enabled. Datasource [datasources/local-metrics.yaml](datasources/local-metrics.yaml).
Catalog [../operations/observability.md](../operations/observability.md).

## Alerting

Conditions under [alerting/](alerting/).

## Review cadence

Review on ADR-level transport or crypto changes.
