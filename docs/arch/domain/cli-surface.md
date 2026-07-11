# CLI Surface — Merkle

## Purpose

Documents the operator-facing `merkle` CLI as a driving adapter over the
Companion Socket. The CLI never opens the keystore or SQLite directly.

## Binary

* Package: `bin/merkle-cli`
* Install name: `merkle`
* Transport: HTTP/1.1 over Unix domain socket (`MERKLE_SOCKET` / XDG default)

## Command groups

| Command | Role |
|---|---|
| `init` | Bootstrap ceremony (ADR-0021); prints recovery key once |
| `unseal` / `seal` / `status` | Lifecycle |
| `doctor` | Multi-check diagnostics (sealed-safe where possible) |
| `bind` | Namespace bind (cwd-aware) |
| `put` / `list` / `get` / `describe` / `search` | Secrets public surface |
| `rotate` / `rollback` / `delete` | Version lifecycle (rollback = append-copy, ADR-0014) |
| `reveal` | Explicit plaintext (operator confirmation) |
| `audit` / `audit rebaseline` | Query + trusted baseline (rebaseline not MCP) |
| `backup` / `restore` | Dual-recipient backups |
| `device` | Companion device list/revoke |
| `verify-recovery-key` | Recovery key check |

Nested: `backup`, `restore`, and `device` expose subcommands.

## Output

* Human-readable by default for status/doctor.
* Machine-oriented JSON where flags allow (see CLI help).

## Invariants

1. Same-UID peer-cred to the agent; no trusted client headers.
2. Destructive/sensitive paths require operator confirmation at the agent.
3. Secrets are not echoed to logs; handles and public metadata only.
4. CLI is interchangeable with MCP for socket-backed ops (ADR-0024).

## Observability

CLI failures surface agent problem details; use `merkle doctor` for aggregate
health. Metrics remain on the agent, not the CLI process.
