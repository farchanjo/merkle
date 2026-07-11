# Operations Overview — Merkle

## Purpose

Index of operational concerns for running Merkle in developer and production-like
environments. Detailed procedures live in sibling documents.

## Overview

Merkle runs as a long-lived per-user agent with thin CLI and MCP clients. Operators
install signed binaries, start the LaunchAgent (or equivalent), unseal when needed,
and use doctor/status for health.

## Scope

| Area | Document |
|---|---|
| Install / upgrade / channels | [deployment.md](deployment.md) |
| Seal, unseal, idle re-lock, lifecycle | [lifecycle.md](lifecycle.md) |
| Logs, metrics, doctor | [observability.md](observability.md) |
| Incident and recovery procedures | [runbook.md](runbook.md) |
| macOS deploy runbook | [../runbooks/deploy.md](../runbooks/deploy.md) |

## Operator surfaces

* CLI binary `merkle`
* MCP adapter `merkle-mcp`
* Companion Socket (sole inbound port)
* LaunchAgent label `dev.fapp.merkle.agent` on macOS

## Health model

1. Process up under the service manager.
2. Socket reachable (`merkle status`).
3. Unsealed when work requires it (idle re-lock may seal — ADR-0031).
4. Audit intact (`merkle doctor`, ADR-0009 / ADR-0029).
5. Backups fresh (ADR-0010, SLO RPO).

## Security ops defaults

* Mode 0600 on socket, keystore, materializations.
* Peer-cred same-UID; optional allowed_consumers globs (ADR-0015 A6).
* Non-loopback metrics require auth_token.
* Never store passphrases in service unit files.

## Observability

See [observability.md](observability.md) and the strategy under
`doc/arch/observability/observability.md`.

## Runbooks

* Deploy: `doc/arch/runbooks/deploy.md`
* General incident: [runbook.md](runbook.md)

## Related ADRs

0002, 0009, 0010, 0015, 0021, 0029, 0030, 0031, 0032
