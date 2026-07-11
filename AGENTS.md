# mcp-vault — Agent Context

Canonical, machine-readable map of this repository for AI agents and
automation. Keep this file dense, factual, and path-anchored.

## Project

Merkle (workspace `mcp-vault`) is a local-first MCP secret vault. Authoritative
**architectural contract**: `docs/arch/` (ADRs, CUE, Rego, Gherkin, OpenAPI,
domain, threat model, SLOs). **Speckit control plane**: `doc/arch/`
(`speckit.toml`, constitution, governance, `sdd/`). Technical slices are
**symlinked** from `docs/arch/` into `doc/arch/`.

## Spec-first protocol

spec-first: `doc/arch` (with symlinks into `docs/arch`) is the validated
control-plane view; behavioral truth for architecture is `docs/arch`. Always:

1. `~/bin/speckit status`
2. `~/bin/speckit next`
3. Read the named spec artifact
4. Change spec and code together
5. `~/bin/speckit validate`

Never invent control-plane state by hand-editing `doc/.specify/*.db`.

## Architecture

```
Claude Code --stdio JSON-RPC--> merkle-mcp --HTTP/UDS--> merkle-agent
Operator ----------------------> merkle CLI -----------> merkle-agent
```

Hexagonal: `merkle-types` ← 6 domain BCs ← `merkle-ports` ← adapters +
`merkle-application`. ADRs of record include 0002, 0009, 0011, 0015, 0021,
0024, 0026, 0028–0032.

Layout:

```
doc/arch/
├── adr/ schemas/ specs/ …   # symlinks → docs/arch/…
├── memory/constitution.md
├── functional/ observability/ quality/ runbooks/
└── sdd/                     # speckit feature workdirs
```

## Commands

```sh
~/bin/speckit status
~/bin/speckit next
~/bin/speckit missing
~/bin/speckit validate
~/bin/speckit reindex
cargo check --workspace --all-targets
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings
make deploy   # macOS release sign+install+kickstart
```

Legacy Makefile `SPEC ?= $(HOME)/bin/spec` targets ADR-0018 lanes when that
binary exists; this host uses `~/bin/speckit` for the control plane.

## Conventions or constraints

* en-US for all persisted artifacts; Angular commits
  `<type>(<scope>): <subject>`.
* Never put secrets in chat, logs, or tool arguments.
* MCP operator confirmation: `_meta` key
  `dev.fapp.merkle/operator_confirmation` = JSON boolean `true` only.
* HTTP proxy: `DestinationPolicy::strict` + connect-time DNS revalidation
  (ADR-0030).
* Empty `allowed_consumers` skips process gate (ADR-0015 Amendment 6).
* Do not weaken workspace lints / `panic=abort` without operator permission.
* **Guard**: `doc/arch/speckit.toml` `[guard] mode = "enforce"` is the
  spec-scope write gate. `speckit on` locks enforcement; `speckit off`
  releases. Out-of-scope edits need deliberate override policy — prefer
  expanding `specScopeGlobs` or working inside an active feature under
  `doc/arch/sdd/`.

## Guard

The guard (`speckit guard`, project lock via `speckit on`/`off`) mediates
writes against the active spec scope (`doc/arch/**`, active `sdd/NNN/**`,
and configured `specScopeGlobs`). Treat enforce mode as the default
expectation when the lock is engaged.
