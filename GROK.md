# mcp-vault — Grok Guide

AGENTS.md is the tool-agnostic canonical map. This file is the Grok-facing twin.

## Project

Merkle local-first MCP vault. Architecture contract docs/arch. Speckit plane doc/arch.

## Spec-first protocol

spec-first: use the installed speckit binary only. Prefer exit code 0 and --json.
Config families: project, adr, guard, git, hygiene, privacy, semantic, context, stats, dedupe.

## Architecture

Crates: merkle-types merkle-ports merkle-application merkle-adapter-companion-socket
merkle-adapter-crypto merkle-adapter-external-services merkle-adapter-keychain
merkle-adapter-mcp merkle-adapter-oob merkle-adapter-sqlite merkle-companion-client
merkle-companion-contract merkle-bdd merkle-e2e merkle-domain-access-mediation
merkle-domain-audit-compliance merkle-domain-backup-recovery merkle-domain-identity
merkle-domain-policy-permissions merkle-domain-secret-storage.

## Commands

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
make check
make test
make lint
make doctor
make doctor-full
make deploy
make build
make build-release
make check
make test
make doctor
```

## Conventions or constraints

Same as AGENTS.md. en-US. Angular subjects <=72 chars. No secrets in chat.
