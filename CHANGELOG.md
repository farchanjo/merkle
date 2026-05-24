# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - Unreleased

### Added

- **Architecture specification** — full domain model documented under `docs/arch/`
  before any implementation begins, following spec-as-source-of-truth discipline
  (ADR-0018).
- **20 Architecture Decision Records (ADRs)** in MADR 4.0 format covering:
  implementation language (Rust 2024 edition, ADR-0001), agent + MCP adapter
  topology (ADR-0002), per-blob encryption with XChaCha20-Poly1305 (ADR-0003),
  BLAKE3 hash chain for audit entries (ADR-0009), slash-only Reveal with OOB
  Confirmation for high-sensitivity secrets (ADR-0011), `age` encryption for
  backups and recovery (ADR-0006), Argon2id key hardness floor (ADR-0005), eleven
  built-in secret categories + CUE schema for custom (ADR-0012), Structurizr C4
  workspace (ADR-0013), `rmcp` official Rust SDK for MCP (ADR-0016), `keyring`
  crate for multi-OS keychain (ADR-0015), full-coverage validation as architectural
  contract (ADR-0018), and more.
- **48 CUE schemas** defining all domain value objects, aggregate roots, and
  per-category secret shapes across six bounded contexts (IdentityAndSealing,
  SecretStorage, AccessMediation, AuditCompliance, BackupRecovery,
  PolicyPermissions).
- **9 Gherkin feature files** covering acceptance scenarios for vault init, secret
  CRUD, namespace binding, Reveal authorization flow, OOB Confirmation, audit chain
  verification, backup and recovery, policy gates, and companion device enrollment.
- **9 Rego policy files** with 123 unit tests enforcing cross-namespace access
  control, rate limiting, reveal authorization, sensitivity classification, and
  audit entry integrity.
- **43 OpenSLO YAML** files defining availability, latency, error-rate, and
  throughput SLOs for each bounded context and integration boundary.
- **2 TLA+ formal models** covering the OOB Confirmation state machine and the
  audit hash chain append protocol.
- **6 domain narrative documents** providing human-readable bounded-context
  descriptions with ubiquitous language glossary references.
- **Structurizr C4 workspace** (`docs/arch/architecture/workspace.dsl`) with
  System Context, Container, and Component diagrams for all six bounded contexts.
- **Canonical glossary** (`docs/arch/glossary.md`) defining all domain terms used
  in the specification, grouped by bounded context.
- **Integration guides** — onboarding walkthrough (`docs/arch/integrations/onboarding.md`)
  and Claude Code wiring guide (`docs/arch/integrations/claude-code-wiring.md`)
  documenting the full operator experience from `merkle init` through working MCP
  sessions.
- **Threat model** under `docs/arch/threat-model/` with STRIDE analysis and trust
  boundary documentation.
- **Operations documentation** under `docs/arch/operations/` covering deployment,
  service registration, and runbooks.
- **Rust workspace bootstrap** — 16 crates across six bounded-context libraries,
  MCP adapter, CLI binary, crypto adapter, keychain adapter, storage adapter, and
  integration test harness.
- **CI pipeline** with 14-validator spec gate (`spec validate --lane full`):
  `lint_yaml`, `lint_cue`, `lint_ddd`, `lint_openapi`, `lint_asyncapi`, `lint_slo`,
  `lint_vale`, `lint_conftest`, `lint_gherkin`, `lint_structurizr`, `lint_markdown`,
  `lint_format`, `run_tlc`, `validate_coverage`.
- **Root documentation** — `README.md`, `LICENSE` (Apache-2.0), `CONTRIBUTING.md`,
  `SECURITY.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).

### Pending

- Implementation phase: Vault Agent daemon, MCP Adapter, CLI binary, Storage
  Adapter (SQLite WAL), Keychain Adapter, Crypto Adapter, OOB Notifier, SSH Bridge,
  HTTP Bridge, Companion Socket, backup scheduler, audit chain writer, and
  integration test suite against all Gherkin features.

---

[0.1.0]: https://github.com/farchanjo/merkle/releases/tag/v0.1.0
