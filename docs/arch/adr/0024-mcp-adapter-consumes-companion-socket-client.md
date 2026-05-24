---
status: accepted
date: 2026-05-24
deciders: [farchanjo]
consulted: [Architecture]
informed: [Engineering, SRE, Security]
---

# 0024. MCP Adapter Consumes Companion Socket Client

## Context and Problem Statement

ADR-0002 prescribes that the MCP Adapter is an external client of the Companion
Socket driving port; it must never hold a direct reference to `AppContext` or
any domain command struct. Two concrete violations exist in the current codebase:

1. `crates/merkle-adapter-mcp/src/lib.rs` documents and implements
   `MerkleMcpServer::new(ctx: Arc<AppContext>)`, importing
   `merkle_application::commands::*` directly. Every tool call bypasses the
   Companion Socket entirely; the socket authentication (PID check, process
   allowlist) is never exercised.

2. `bin/merkle-agent/src/run.rs:386` defines `mcp_task`, which starts the rmcp
   stdio server _inside_ the Vault Agent daemon using the daemon's own stdin
   and stdout. This means only one Claude Code window can connect at a time, and
   any window that closes takes the daemon's stdio with it. Multi-window MCP —
   the core motivation of ADR-0002 — is impossible in this configuration.

A third operational consequence: the Claude Code configuration calls
`merkle mcp` as the MCP server command. That subcommand does not exist in the
current `bin/merkle-cli` surface, so the MCP server fails to start entirely.

## Decision Drivers

* **Single-unseal invariant**: exactly one Vault Agent process holds the Vault
  Root Key in mlocked memory; nothing else may call the domain layer directly.
* **Serialized SQLite writes**: only the Vault Agent writes to SQLite; any
  per-process `AppContext` in an MCP binary would introduce concurrent writers.
* **Multi-window MCP**: each Claude Code window spawns its own thin
  `bin/merkle-mcp` binary connected to the running agent over the Companion
  Socket; the agent is undisturbed when any window closes.
* **ADR-0002 compliance**: the Companion Socket is the single inbound driving
  port; all callers are external clients, not in-process adapters.
* **Spec validation alignment**: `spec validate` must remain green throughout
  the migration; no lane may regress.

## Considered Options

* **Option A**: Introduce a `CompanionSocketClient` driving-port client;
  refactor `crates/merkle-adapter-mcp` to use it; introduce a new thin
  `bin/merkle-mcp` binary that connects to the agent over the Companion Socket
  and serves MCP stdio. (Recommended)
* **Option B**: Keep the MCP server inside the agent daemon; expose multiple
  stdio streams via multiplexing inside a single process.
* **Option C**: Introduce a per-process `AppContext` in a standalone
  `bin/merkle-mcp` binary that opens SQLite and holds its own key material.

## Decision Outcome

Chosen option: **Option A — `CompanionSocketClient` + thin `bin/merkle-mcp`
binary**.

Option B violates the MCP specification: the stdio transport binds one process
to one client. A shared persistent MCP server with multiple stdio streams has
no standard mechanism and is rejected by every tested MCP host (Claude Code,
Cursor). The agent daemon's stdio is also unsuitable as a transport because the
daemon logs to stdout and the process is not designed to be a client-facing
server.

Option C violates the single-writer SQLite invariant established in ADR-0002
and ADR-0003. Multiple unseal sessions would be required, contradicting the
primary motivation of the agent topology.

Option A preserves all invariants: the agent is the sole SQLite writer and key
holder; each `bin/merkle-mcp` instance is a stateless translation layer that
speaks JSON-RPC over the Companion Socket.

### Consequences

* Good, because `bin/merkle-mcp` is a thin process with no crypto
  responsibilities; it can be updated, crashed, or restarted independently of
  the agent.
* Good, because multiple Claude Code windows each get their own `merkle-mcp`
  process; the agent is unaffected by window lifecycle.
* Good, because the Companion Socket PID + allowlist authentication is exercised
  on every MCP tool call, fulfilling ADR-0002 security intent.
* Good, because `spec validate` can be kept green incrementally by migrating
  tool groups in separate PRs (see Migration Plan below).
* Bad, because every MCP tool call now crosses an IPC boundary (Unix socket)
  where it previously was an in-process function call; latency increases by
  roughly one round-trip per tool invocation (~1 ms on loopback).
* Bad, because `crates/merkle-companion-client` is a new crate to maintain,
  adding a dependency to `crates/merkle-adapter-mcp` and `bin/merkle-mcp`.

## Gap Matrix

`crates/merkle-adapter-mcp/src/lib.rs` documents 29 MCP tools. The existing
Companion Socket exposes 19 endpoints. The table below maps each tool group to
coverage status.

| Tool group | Tools | Socket endpoint status |
|---|---|---|
| Identity — unseal, seal | 2 | Covered (`POST /v1/agent/unseal`, `POST /v1/agent/seal`) |
| Identity — bind | 1 | Needs reconciliation (see Note 1) |
| Secrets — put, get, list, describe, search, rotate, delete, history | 8 | Covered (`/v1/secrets/*`) |
| Reveal | 1 | Covered (`POST /v1/secrets/:handle/reveal`) |
| Audit | 1 | Covered (`GET /v1/audit`) |
| Backup, restore | 2 | Covered (`POST /v1/backup`, `POST /v1/restore`) |
| Use-token — use, write_tempfile, write_fifo, revoke_tempfile | 4 | **Missing** — PR3 adds `/v1/use-token/*` |
| Proxy — ssh.exec, ssh.copy, ssh.port_forward, ssh.shell, http.request, http.download, http.upload, spawn, crypto.sign, crypto.decrypt | 10 | **Missing** — PR4 adds `/v1/key-material/*` (see Note 2) |
| Diagnostics — doctor | 1 | **Missing** — PR2 adds `/v1/agent/doctor` |

**Total covered**: 14. **Total missing**: 15.

**Note 1 — `vault.bind` vs `CreateSessionRequest`**: The MCP `vault.bind` tool
maps to `BindNamespaceCommand` in `merkle-application`. The existing socket
exposes `POST /v1/sessions` (`CreateSessionRequest`), which uses a different
request model. PR2 must reconcile these two representations before migrating the
tool.

**Note 2 — Proxy tool execution split**: Proxy tools (ssh, http, spawn, crypto)
execute their I/O _inside the MCP process_, not inside the agent. The agent's
role is to mint a short-lived Use Token and reveal the key material bytes needed
for the MCP process to perform the operation locally. Only the Use Token mint
and key-material reveal cross the socket; the actual SSH/HTTP/process execution
stays in `bin/merkle-mcp`. This preserves the single-writer invariant while
avoiding the overhead of streaming large payloads (file downloads, shell output)
through the agent.

## Migration Plan / PR Sequencing

The following PRs are operator commitments, executed in order:

**PR1 — Extract `CompanionSocketClient`**
Create `crates/merkle-companion-client` with a typed async client for the
Companion Socket JSON-RPC protocol. No changes to `merkle-adapter-mcp` yet.
In-flight in parallel with this ADR.

**PR2 — Reconcile bind + add doctor + migrate 14 covered tools**
Reconcile `BindNamespaceCommand` vs `CreateSessionRequest`; add
`GET /v1/agent/doctor` endpoint; refactor the 14 already-covered MCP tools
(identity unseal/seal, secrets CRUD, reveal, audit, backup/restore) in
`crates/merkle-adapter-mcp` to call `CompanionSocketClient` instead of
`merkle_application` commands directly.

**PR3 — Add `/v1/use-token/*` endpoints**
Add socket endpoints and DTOs for `vault.use`, `vault.write_tempfile`,
`vault.write_fifo`, and `vault.revoke_tempfile`. Migrate the 4 use-token MCP
tools.

**PR4 — Add `/v1/key-material/*` endpoints**
Add socket endpoints that mint a Use Token and return the key-material bytes
needed for client-side execution. Migrate the 10 proxy MCP tools to perform
their I/O locally using the minted credentials.

**PR5 — Create `bin/merkle-mcp`; remove `mcp_task` from agent**
Introduce the thin `bin/merkle-mcp` stdio binary. Remove the `mcp_task`
function from `bin/merkle-agent/src/run.rs`. Update `~/.claude.json` (or
equivalent MCP host config) to spawn `merkle-mcp` instead of `merkle mcp`.

**PR6 — Drop `merkle-application` dep from MCP adapter**
Remove `merkle-application` and `merkle-domain-*` from
`crates/merkle-adapter-mcp/Cargo.toml`. Verify via `cargo build` that no
`AppContext` reference remains in the adapter crate. This is the final
compliance gate for ADR-0002.

## Validation

* `spec validate` exits 0 with all lanes green after each PR. The `lint_madr`
  lane must count 24 ADRs starting from this ADR.
* After PR6: `cargo build --workspace` exits 0 with `merkle-application` absent
  from `crates/merkle-adapter-mcp`'s transitive dependency graph.
* After PR5: integration test — spawn two `merkle-mcp` processes against one
  running `merkle-agent`; call `vault.list` concurrently from both; assert no
  `SQLITE_BUSY` errors and identical result sets.
* `cargo clippy --all-features --all-targets --workspace -- -D warnings` exits
  0 after each PR.

## More Information

* [ADR-0002](0002-adopt-agent-plus-mcp-adapter-topology.md) — the topology this
  ADR corrects the implementation to match.
* [ADR-0016](0016-rmcp-official-rust-sdk-for-mcp.md) — rmcp SDK choice; the
  `ServiceExt` trait used by `MerkleMcpServer`.
* [ADR-0022](0022-file-backed-keystore-for-headless-contexts.md) — file keystore
  used by the agent in headless contexts; `bin/merkle-mcp` must not open it.
* `crates/merkle-adapter-mcp/src/lib.rs` — current violation: direct
  `AppContext` dependency documented in module doc comment.
* `bin/merkle-agent/src/run.rs:386` — current violation: `mcp_task` binds MCP
  stdio to the daemon process.

## Follow-up — 2026-05-24

A live integration smoke test run against `merkle-agent` immediately after
the Phase-2 merge (this ADR) surfaced five bugs catalogued in
[ADR-0025](0025-post-phase-2-cosmetic-cleanup.md).

Summary of bugs found:

* **Bug #1** — Handle URI encodes raw secret name instead of bound namespace
  label; breaks stable cross-session references (ADR-0008 violation).
* **Bug #2** — `Storage::list_namespaces()` port method missing; `GET
  /v1/namespaces` returns empty list silently (OpenAPI contract violation).
* **Bug #3** — `vault.audit.query?verify_chain=true` returns `chain_valid:
  null`; ChainVerifier never invoked (ADR-0009 violation).
* **Bug #5** — CLI `merkle unseal` prints incorrect "already unsealed" message
  on a successful sealed-to-unsealed transition (UX regression).
* **Bug #6** — `vault.bind` docstring implies `cwd_hash` is an exposed MCP
  parameter; it is an internal adapter implementation detail (ADR-0008
  documentation gap).

Bug #4 (OOB notifier doctor fail) is a macOS notification-permission
platform requirement, not a code bug; tracked as a platform-setup task.

All five in-scope bugs are remediated in targeted PRs governed by ADR-0025.
The smoke test sequence (doctor → bind → put → list → describe →
audit_query with verify_chain) must pass end-to-end after those PRs merge.
