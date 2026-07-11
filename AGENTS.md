# mcp-vault — Agent Context

Canonical, machine-readable map of this repository for AI agents and
automation. Keep this file dense, factual, and path-anchored.

## Project

Merkle (workspace name mcp-vault) is a local-first MCP secret vault.
Authoritative architectural contract: `docs/arch/` (ADRs, CUE, Rego, Gherkin,
OpenAPI, domain, threat model, SLOs). Speckit control plane: `doc/arch/`
(speckit.toml, constitution, governance, sdd/). Technical slices are symlinked
from `docs/arch/` into `doc/arch/`.

## Spec-first protocol

spec-first: `doc/arch` (with symlinks into `docs/arch`) is the validated
control-plane view; behavioral truth for architecture is `docs/arch`. Always:

1. `speckit status`
2. `speckit next`
3. Read the named spec artifact
4. Change spec and code together
5. `speckit validate`

Never invent control-plane state by hand-editing databases under `doc/.specify`.
Use the installed `speckit` binary on the operator PATH.

## Architecture

```
Claude Code --stdio JSON-RPC--> merkle-mcp --HTTP/UDS--> merkle-agent
Operator ----------------------> merkle CLI -----------> merkle-agent
```

Hexagonal crates: `merkle-types`, domain BCs, `merkle-ports`, `merkle-application`, `merkle-adapter-companion-socket`, `merkle-adapter-crypto`, `merkle-adapter-external-services`, `merkle-adapter-keychain`, `merkle-adapter-mcp`, `merkle-adapter-oob`, `merkle-adapter-sqlite`, `merkle-companion-client`, `merkle-companion-contract`, `merkle-bdd`, `merkle-e2e`, `merkle-domain-access-mediation`, `merkle-domain-audit-compliance`, `merkle-domain-backup-recovery`, `merkle-domain-identity`, `merkle-domain-policy-permissions`, `merkle-domain-secret-storage`. ADRs of record include 0002, 0009, 0011, 0015, 0021,
0024, 0026, and 0028 through 0032.

## Commands

Speckit leaf commands (complete catalog for agent coverage):

```text
speckit analyze
speckit ask
speckit brief
speckit check
speckit clarify
speckit commit check
speckit commit suggest
speckit completions
speckit config drift
speckit config get
speckit config list
speckit config set
speckit config unset
speckit constitution
speckit context pack
speckit context score
speckit dedupe
speckit diagram render
speckit dismiss
speckit explain
speckit feature archive
speckit feature compact
speckit feature insert
speckit feature list
speckit feature new
speckit feature renumber
speckit feature reorder
speckit feature restore
speckit feature select
speckit gitlab status
speckit gitlab sync
speckit guard check
speckit guard hook
speckit guide
speckit hook post-edit
speckit hook pre-commit
speckit hook session-start
speckit hook user-prompt
speckit implement
speckit init
speckit library add
speckit library ask
speckit library browse
speckit library export
speckit library extract
speckit library import
speckit library list
speckit library open
speckit library remove
speckit library search
speckit library serve
speckit library show
speckit library update
speckit library validate
speckit license check
speckit license list
speckit license set
speckit license show
speckit manual
speckit mermaid render
speckit migrate
speckit missing
speckit model add
speckit model api apply
speckit model api list
speckit model api select
speckit model check
speckit model fetch
speckit model list
speckit model remove
speckit model select
speckit next
speckit off
speckit on
speckit pack add
speckit pack export
speckit pack import
speckit pack list
speckit pack remove
speckit pack update
speckit plan
speckit plan setup
speckit reindex
speckit search
speckit semantic deep-status
speckit semantic enable
speckit semantic eval
speckit semantic off
speckit semantic status
speckit spec score
speckit specify
speckit stats attributes
speckit stats compliance
speckit stats corpus
speckit stats findings
speckit stats guard
speckit stats profile
speckit stats recommendations
speckit status
speckit tasks
speckit tasks setup
speckit validate
speckit verify
speckit version
speckit workflow render
```

Make targets used in this repo:

```text
make check
make test
make lint
make doctor
make doctor-full
make deploy
make build
make build-release
make sign
make install
make kickstart
```

## Conventions or constraints

* en-US for all persisted artifacts; Angular commits with subject at most 72 chars.
* Never put secrets in chat, logs, or tool arguments.
* MCP operator confirmation uses the meta key
  dev.fapp.merkle operator_confirmation equal to JSON boolean true (MERK-001).
* HTTP proxy uses DestinationPolicy strict mode and connect-time DNS revalidation (ADR-0030).
* Empty allowed_consumers skips the process gate (ADR-0015 Amendment 6).
* Do not weaken workspace lints or release panic=abort without operator permission.
* Guard: `doc/arch/speckit.toml` guard mode enforce is the write gate.
  Use `speckit on` and `speckit off`. Prefer `specScopeGlobs` or the sdd directory under doc/arch (feature workdirs).

## Guard

The guard (`speckit guard check`, lock via `speckit on` / `speckit off`) mediates
writes against active spec scope (`doc/arch/**`, active sdd feature dirs, and
configured `specScopeGlobs`). Enforce mode is the default expectation when locked.

## Contracts and config families

* Prefer `speckit ... --json` for machine-readable output in automation.
* Treat non-zero **exit code** from `speckit validate` as a hard gate (exit 0 only
  when findings are absent or fully waived).
* Config families operators may touch via `speckit config`: guard, git, project,
  semantic, context, hygiene, privacy, stats, dedupe, and related embedded keys.
  See `speckit config list` and `doc/arch/speckit.toml`.
