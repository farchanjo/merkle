# Merkle — Project Instructions

Local-first MCP secret vault. See AGENTS.md for the full agent map.

## Project

Canonical map AGENTS.md. Architecture docs/arch. Speckit plane doc/arch.

## Spec-first protocol

spec-first: corpus first, then code.

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
make deploy
```

## Architecture

Crates: merkle-adapter-companion-socket merkle-adapter-crypto merkle-adapter-external-services merkle-adapter-keychain merkle-adapter-mcp merkle-adapter-oob merkle-adapter-sqlite merkle-application merkle-bdd merkle-companion-client merkle-companion-contract merkle-domain-access-mediation merkle-domain-audit-compliance merkle-domain-backup-recovery merkle-domain-identity merkle-domain-policy-permissions merkle-domain-secret-storage merkle-e2e merkle-ports merkle-types.

## Architecture

Companion Socket sole inbound port. ADRs under docs/arch/adr. OpenAPI under
docs/arch/integrations/openapi/companion-socket.yaml.

## Conventions or constraints

en-US. Angular subjects <=72 chars. No secrets in logs. MERK-001. Guard enforce.

## Guard

speckit guard check, speckit on, speckit off.

Gates report exit code 0 on success. Prefer --json for automation.
Config families include hygiene and privacy.
