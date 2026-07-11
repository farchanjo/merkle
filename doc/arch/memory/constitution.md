# Merkle Constitution

This constitution binds every design, ADR, and implementation decision for the
**Merkle** local-first MCP secret vault (`mcp-vault` repository). Specs under
`docs/arch/` (mirrored into the speckit control plane under `doc/arch/`) are the
source of truth; code implements the spec, never the reverse.

## Principles

1. **Local-first, operator-owned.** Secrets and key material stay on the
   operator machine. No cloud vault backend is required for core operation.
2. **LLM never sees plaintext by default.** Opaque handles are the default
   exposure; reveal and materialization are opt-in, audited, and gated
   (ADR-0007, ADR-0011, MERK-001 `_meta`).
3. **One inbound port.** All privileged vault operations enter the daemon only
   through the Companion Socket (HTTP/1.1 over a Unix domain socket). CLI and
   MCP are thin clients (ADR-0002, ADR-0024).
4. **Hexagonal + DDD.** Domain crates depend only on `merkle-types` and std.
   Application orchestrates ports; adapters implement them. No infra leaks
   inward.
5. **Tamper-evident audit.** Every security-relevant op appends to a BLAKE3
   hash chain with keyed pinned head in SQLite (ADR-0009). Fail closed on
   verification errors.
6. **Fail closed.** Auth, policy, SSRF, peer-cred, and OOB gates deny on
   ambiguity. Test-only permissive paths never ship in production wiring.
7. **Spec-first.** Behavioral changes update `docs/arch/` (ADRs, OpenAPI,
   Gherkin, CUE, domain docs) in the same commit train as code. Speckit
   (`~/bin/speckit`) manages SDD workflow under `doc/arch/`; the rich corpus
   remains the architectural contract.
8. **Defensive security only.** Authentication, mTLS-class local peer trust,
   secrets handling, TLS, and hardening are in scope. Offensive dual-use
   tooling is out of scope.
9. **Clarity over cleverness.** Every design choice must be explainable to a
   newcomer in a short paragraph; ADRs capture rejected alternatives.
10. **Reproducibility.** Builds pin toolchain and dependencies; release
    binaries are signed; config rejects unknown fields.

## Constraints

* Language: Rust, edition and MSRV as in `rust-toolchain.toml` / ADR-0001.
* Workspace lints and `panic = "abort"` in release are locked — fix code, not
  the lint baseline, without explicit operator permission.
* Secrets in chat, logs, or MCP tool arguments are forbidden; use vault proxy
  tools and Merkle MCP patterns.
* English (en-US) for all persisted artifacts (code, docs, commits, ADRs).

## Governance

* Structural architectural change requires an accepted MADR under
  `docs/arch/adr/` (also visible via `doc/arch/adr` symlink).
* Trivial typo/format fixes may land without a new ADR; decision changes may
  not.
* Speckit project lock (`speckit on`) forces guard enforcement for out-of-scope
  edits; operators release with `speckit off` only deliberately.
* Amendments to this constitution require an ADR with status `accepted` and a
  non-empty `deciders` entry.
