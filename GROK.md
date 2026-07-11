# mcp-vault — Grok Build Guide

`AGENTS.md` is the tool-agnostic project map; this file adds Grok-specific notes.

## Project

Merkle local-first MCP vault. Spec-driven: architectural corpus in `docs/arch/`,
speckit plane in `doc/arch/` (symlinks + governance).

## Spec-first protocol

spec-first: read the corpus before code. Drive the loop with:

* `~/bin/speckit status`
* `~/bin/speckit next`
* `~/bin/speckit validate`

Binary-only: use `~/bin/speckit`, never the speckit source tree.

## Architecture

Agent daemon owns keys/storage/audit; CLI and MCP are Companion Socket clients.
Proxy I/O runs in the agent (ADR-0024 amendment). See `AGENTS.md` for the map.

## Commands

```sh
~/bin/speckit status
~/bin/speckit next
~/bin/speckit missing
~/bin/speckit validate
cargo check --workspace --all-targets
make deploy
```

## Conventions or constraints

* Same hard rules as `AGENTS.md` (secrets, `_meta` confirmation, SSRF, guard).
* Prefer Read/Edit tools over shell file rewrites.
* Parallel work: keep ADR numbers sequential under `docs/arch/adr/`.
* Dual corpus: never fork ADRs into only one of `doc/` vs `docs/`.
