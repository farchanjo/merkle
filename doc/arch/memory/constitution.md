# Merkle Constitution

This constitution binds every design, ADR, and implementation decision for the
Merkle local-first MCP secret vault. Specs under docs/arch (mirrored into the
speckit control plane under doc/arch) are the source of truth; code implements
the spec, never the reverse.

## Principles

1. Local-first, operator-owned. Secrets stay on the operator machine.
2. LLM never sees plaintext by default. Opaque handles; reveal is gated.
3. One inbound port. Companion Socket only for privileged vault operations.
4. Hexagonal plus DDD. Domain depends only on merkle-types and std.
5. Tamper-evident audit. BLAKE3 chain with keyed pinned head in SQLite.
6. Fail closed. Auth, policy, SSRF, peer-cred, and OOB deny on ambiguity.
7. Spec-first. Behavioral changes update docs/arch in the same change train.
8. Defensive security only. Offensive dual-use tooling is out of scope.
9. Clarity over cleverness. ADRs capture rejected alternatives.
10. Reproducibility. Pin toolchain and dependencies; release binaries signed.

## Constraints

* Language: Rust as in rust-toolchain.toml and ADR-0001.
* Workspace lints and release panic=abort are locked without operator permission.
* Secrets never appear in chat, logs, or tool arguments.
* English en-US for all persisted artifacts.

## Governance

* Structural change requires an accepted MADR under docs/arch/adr.
* Trivial typo fixes may land without a new ADR.
* Speckit project lock (speckit on) forces guard enforcement.
* Amendments to this constitution require an accepted ADR with deciders.
