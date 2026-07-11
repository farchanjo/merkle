# Operations Overview — Merkle

## Purpose

Operational index for Merkle agent, CLI, and MCP.

## Overview

Long-lived agent; thin CLI and MCP clients over the Companion Socket.

## Environment Variables

| Variable | Role |
|---|---|
| MERKLE_SOCKET | Socket path override |
| MERKLE_CONFIG | Config path override |
| MERKLE_KEYSTORE_PASSPHRASE | File keystore passphrase |
| MERKLE_KEYSTORE_PATH | File keystore path |
| MERKLE_RECOVERY_RECIPIENT | age recipient at startup |
| MERKLE__STORAGE__DATABASE_URL | SQLite URL |
| MERKLE__COMPANION_SOCKET__PATH | Socket via config overlay |
| MERKLE__KEYSTORE__BACKEND | os, file, or auto |
| MERKLE__METRICS__ENABLED | Metrics toggle |

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Runtime failure |
| 2 | Usage error |
| 3 | Policy denied |
| 4 | Not found |
| 5 | Storage or keychain error |

## Scope

| Area | Document |
|---|---|
| Install | [deployment.md](deployment.md) |
| Lifecycle | [lifecycle.md](lifecycle.md) |
| Logs | [observability.md](observability.md) |
| Incidents | [runbook.md](runbook.md) |
| Deploy | [../runbooks/deploy.md](../runbooks/deploy.md) |

## Operator surfaces

merkle CLI, merkle-mcp, Companion Socket, LaunchAgent.

## Health model

Process up; socket reachable; unsealed when needed; audit intact; backups fresh.

## Security ops defaults

Mode 0600 materials; peer-cred; metrics auth_token off-loopback.

## Observability

See [observability.md](observability.md).

## Runbooks

[deploy.md](../runbooks/deploy.md) and [runbook.md](runbook.md).
