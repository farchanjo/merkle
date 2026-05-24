---
status: accepted
date: 2026-05-22
deciders: [farchanjo]
consulted: [Architecture]
informed: [Engineering, SRE, Security]
---

# 0018. Full-Coverage Validation as Architectural Contract

## Context and Problem Statement

The Merkle architecture defines five artifact layers beyond MADR prose: CUE
domain schemas, Rego policies, Gherkin acceptance scenarios, Structurizr C4
models, and a `formal/` directory designated for TLA+ specifications. Each
layer is described in `docs/arch/README.md` and referenced by the bounded
context narratives and ADRs as authoritative representations of architectural
intent.

`spec validate --lane full` runs 14 validators across these layers. As of the
date of this record, five validators are routinely skipped because the
corresponding source artifacts do not exist:

- `lint_openapi` — no OpenAPI 3.1 spec for the Companion Socket contract
- `lint_asyncapi` — no AsyncAPI 2.6 spec for audit and OOB event streams
- `lint_slo` — no OpenSLO YAML describing availability and latency objectives
- `lint_vale` — no Vale style pack governing prose consistency across ADRs and
  domain narratives
- `lint_conftest` — companion `_test.rego` files absent for existing policies
- `run_tlc` — no TLA+ specifications for the audit hash chain or AEAD nonce
  uniqueness invariants

A validator that is unconditionally skipped because its source file is absent
is observationally indistinguishable from a validator that is permanently
disabled. CI reports green, but the absence of machine-verifiable contracts
means that architectural properties claimed in prose can diverge from
implementation without any automated detection. This creates a systematic gap
between what the architecture records assert and what the system is actually
constrained to do.

The problem is compounded by the interaction surface: three parallel
agent teams are working on Companion Socket implementation (ADR-0011,
ADR-0016), OOB event emission (ADR-0011), AEAD nonce handling (ADR-0004),
and audit chain integrity (ADR-0009). Without machine-checkable interface
contracts and invariant specifications in place before implementation
converges, the review gate is effectively prose-only, and drift can only be
caught by manual inspection.

This ADR records the decision to treat full-coverage validation — every
validator in `spec validate --lane full` producing a result rather than a skip
— as a first-class architectural contract, not a best-effort aspiration.

## Decision Drivers

* **Drift prevention**: machine-verifiable contracts (OpenAPI, AsyncAPI, Rego
  tests, TLA+ invariants) provide continuous automated enforcement. Prose
  descriptions can be copied, reworded, or silently contradicted; schemas and
  formal specs cannot.
* **CI determinism**: a CI lane where validators are skipped because artifacts
  are absent conflates "no violations found" with "nothing checked." Enforcing
  full coverage makes green CI mean all 14 validators ran and passed, not that
  some subset happened to find no errors.
* **ADR-0009 and ADR-0004 model-checkability**: the audit hash chain
  (ADR-0009) and the AEAD nonce uniqueness guarantee (ADR-0004) are safety
  properties whose violation is catastrophic. TLA+ model checking provides
  exhaustive verification of the state machine that no integration test can
  replicate for all interleavings.
* **Contract-first interaction with the implementation phase**: OpenAPI and
  AsyncAPI specs authored before implementation close the interface before code
  is written. The Companion Socket (driving port) and the OOB Notifier (driven
  port) are cross-process boundaries; their contracts must be precise and
  machine-readable before the implementation agents begin writing transport
  code.
* **SRE handoff**: SLO YAML (OpenSLO) in the arch repo gives the SRE function
  a machine-parseable definition of availability and latency targets. Without
  it, SRE must derive targets from prose, which introduces interpretation error
  and makes alerting thresholds non-reproducible from the architecture.
* **Security review**: Rego companion tests (`_test.rego`) assert that each
  policy gate produces `allow` and `deny` for its expected inputs. Without
  tests, a reviewer must mentally execute the Rego to verify correctness.
  Companion tests are executable ground truth for security review.
* **Downstream code generation**: OpenAPI 3.1 and AsyncAPI 2.6 specs are
  machine-readable sources from which client stubs, server skeletons, and
  documentation can be generated. Treating them as optional artifacts
  permanently forecloses the code-generation path and forces manual
  synchronization between spec and code.

## Considered Options

* Option A: Prose-only artifacts — keep ADR prose as the sole authoritative
  representation; do not require machine-readable contracts
* Option B: Machine artifacts only where strictly required — add artifacts
  selectively when a specific downstream consumer (code generator, linter)
  demands them; skip otherwise
* Option C: Full-coverage validation mandatory — all validators in
  `spec validate --lane full` must produce a result (pass or fail, never skip)
  for every merge to the main branch; absence of a required artifact is
  treated as a validation failure

## Decision Outcome

Chosen option: "Option C: Full-coverage validation mandatory", because it is
the only option that closes the observational gap between "CI is green" and
"the architecture is machine-verified." Options A and B both permit
indefinite deferral of machine contracts, which has already resulted in five
validators being skipped across two or more sprint cycles.

The chosen option is operationalized as follows:

1. The six missing artifact families listed in the context section are
   authored in parallel with this ADR (see More Information).
2. `spec validate --lane full` is added to the merge-request CI pipeline as a
   blocking gate; no merge is permitted while any validator reports SKIP.
3. Adding a new validator to the `spec validate` configuration is treated as
   an architectural change and requires a corresponding ADR or ADR amendment
   before the validator can be added to the blocking gate.
4. The arch repo `README.md` reading order is updated to list the new
   artifact families alongside the existing ones.

### Consequences

* Good, because every merge to main from this point forward is provably
  covered by all 14 validators, eliminating the silent drift path.
* Good, because OpenAPI and AsyncAPI specs authored now serve as the
  implementation contract for the Companion Socket and OOB Notifier; later
  changes to those contracts require explicit ADR review before the validator
  accepts them.
* Good, because TLA+ specs for ADR-0009 (hash chain) and ADR-0004 (nonce
  uniqueness) provide exhaustive model-checking coverage that no property-based
  or integration test can replicate for arbitrary interleavings.
* Good, because Rego companion tests are executable security review artifacts;
  a security auditor can run `conftest verify` and receive a machine-generated
  verdict rather than relying on manual policy reading.
* Bad, because authoring six artifact families in parallel with the
  implementation phase compresses the time available for implementation review;
  the parallelization mitigates but does not eliminate the schedule pressure.
* Bad, because adding TLA+ to the mandatory lane introduces a tool dependency
  (`tlc`) that must be present in CI; the `spec validate` framework already
  provides the binary via `mise`, but any CI agent without network access at
  provision time requires a cached image.
* Neutral, because the Vale style pack enforces prose conventions
  retroactively across 17 existing ADRs; the initial integration will likely
  surface style findings that require minor prose edits before the lane goes
  green for the first time.

## Pros and Cons of the Options

### Option A: Prose-only artifacts

* Good, because no additional tooling or authoring time is required; the
  existing 17 ADRs and domain narratives are sufficient as-is.
* Good, because prose is universally readable without specialist tooling
  (no OpenAPI viewer, no TLC binary, no Conftest runtime).
* Bad, because prose cannot be executed, diffed against running code, or
  fed into a code generator; machine contracts are necessary for all
  three activities.
* Bad, because architectural drift from prose to implementation is
  undetectable until a human reviewer notices the discrepancy; the gap
  between ADR-0009 prose and a subtly incorrect hash-chain implementation
  could persist through multiple releases.
* Bad, because skipped validators present a false assurance signal in CI;
  "all checks passed" includes checks that did not run.

### Option B: Machine artifacts only where strictly required

* Good, because artifacts are added only when a concrete downstream consumer
  demands them, avoiding speculative investment in schemas that may never
  be used.
* Good, because it minimizes the initial authoring burden and lets the team
  prioritize implementation.
* Bad, because "strictly required" is evaluated per-consumer at the time
  of integration, which defers the architectural contract decision until
  after the implementation has already diverged from the implicit contract.
* Bad, because selective coverage creates a two-tier validation system where
  some bounded contexts are machine-verified and others are not; this
  asymmetry is invisible in CI and compounds over time as the covered
  portion grows stale.
* Neutral, because the criteria for "strictly required" must be codified
  somewhere; in practice this ADR would be replaced by a more complex
  decision table that re-litigates coverage per feature, adding process
  overhead without architectural clarity.

### Option C: Full-coverage validation mandatory (chosen)

* Good, because the CI signal becomes unambiguous: green means all
  14 validators ran and found no violations, without exception.
* Good, because OpenAPI, AsyncAPI, and TLA+ specs authored before
  implementation close the interface contract early, when changing it
  is cheap.
* Good, because Rego companion tests and Vale style packs enforce
  consistency that would otherwise require manual review on every PR.
* Bad, because the initial investment to author all six artifact families
  is non-trivial and compresses the implementation timeline.
* Bad, because any new validator added to the `spec validate` configuration
  immediately blocks CI until a corresponding artifact is authored; this is
  a feature (prevents silent skips) but requires team discipline around
  validator additions.

## Validation

- `spec validate --lane full` exits 0 with all 14 validators in `ok` state —
  `lint_yaml`, `lint_openapi`, `lint_asyncapi`, `lint_slo`, `lint_vale`,
  `lint_conftest`, and `run_tlc` MUST NOT report `skipped` on CI.
- Pre-merge hook blocks any addition of validators without an `## Amendment`
  to this ADR.
- The validator-to-artifact map (in `## More Information`) is a CI-tested
  cross-reference; the CI job `validator-coverage` asserts every validator has
  source artifacts.

## More Information

The following artifacts are being authored in parallel with this ADR by
specialist agents. Each artifact unlocks the indicated validator:

| Artifact | Format | Validator unlocked | Relevant ADR(s) |
|---|---|---|---|
| Companion Socket contract | OpenAPI 3.1 YAML | `lint_openapi` | ADR-0011, ADR-0016 |
| Audit and OOB event streams | AsyncAPI 2.6 YAML | `lint_asyncapi` | ADR-0009, ADR-0011 |
| Service-level objectives | OpenSLO YAML | `lint_slo` | ADR-0001, ADR-0009 |
| Prose style pack | Vale YAML rules | `lint_vale` | All ADRs |
| Rego companion tests | `_test.rego` files | `lint_conftest` | ADR-0009, ADR-0011 |
| Hash chain TLA+ spec | TLA+ module | `run_tlc` | ADR-0009 |
| AEAD nonce uniqueness TLA+ spec | TLA+ module | `run_tlc` | ADR-0004 |

## Amendment — 2026-05-23 — Init Bootstrap, Unseal Rollback, and Payload Format

Three bugs discovered during smoke testing revealed gaps in the architectural
specification that required spec updates before implementation.

### Bug 1 — Init Vault Bootstrap (ADR-0021)

`merkle init --non-interactive` printed "ok" without calling any agent
endpoint. Decision: the bootstrap ceremony is specified as `POST /v1/agent/init`
on the Companion Socket. See [ADR-0021](0021-init-vault-bootstrap-ceremony.md)
for the eight-step atomic ceremony, idempotency contract, Recovery Key display
rules, and the new `"init"` value added to `#AuditOp`.

### Bug 2 — Unseal Error Rollback (ADR-0015 Amendment 3)

`id_guard.begin_unseal()` transitioned state to `Unsealing` and failed to
revert on error; retries received "invalid state transition from Unsealing to
Unsealing." Decision: any error during the Unseal Protocol MUST revert state
to `Sealed` before propagating. See ADR-0015 Amendment 3 for the RAII
`UnsealGuard` pattern and the enumerated failure modes. The domain narrative
`identity-and-sealing.md` now contains an `## Error Rollback Contract`
subsection. Three new Gherkin scenarios were added to `unseal.feature`.

### Bug 3 — PutSecretRequest Payload Format Decision

`PutSecretRequest.value` was typed as `object` with no format declaration,
leaving payload encoding ambiguous (JSON-enveloped, raw base64, raw binary
stream). Decision: `value` is a `string`; a new required field `value_format`
declares `"utf8"` or `"base64"` encoding. Binary payloads MUST use
`value_format=base64`. Category-specific supplementary fields go in
`category_fields` (optional `object additionalProperties: true`). Raw binary
stream and base64-only approaches were both rejected. Three Gherkin scenarios
were added to `put_secret.feature`. The glossary entry `Value Format` was added.

Cross-references to existing ADRs that motivated this decision:

* [0001-use-rust-as-implementation-language.md](0001-use-rust-as-implementation-language.md) — implementation
  language choice that the TLA+ and OpenAPI contracts must be consistent with.
  See also: ADR-0001 `## More Information` backlinks this ADR.
* [0004-xchacha20-poly1305-aead-for-blobs.md](0004-xchacha20-poly1305-aead-for-blobs.md) — nonce
  uniqueness guarantee that the TLA+ spec formally verifies.
  See also: ADR-0004 `## More Information` backlinks this ADR.
* [0009-merkle-style-audit-hash-chain.md](0009-merkle-style-audit-hash-chain.md) — hash chain
  integrity invariant that both the TLA+ spec and the AsyncAPI audit-event
  schema machine-verify.
  See also: ADR-0009 `## More Information` backlinks this ADR.
* [0011-slash-only-reveal-with-oob-for-high-sensitivity.md](0011-slash-only-reveal-with-oob-for-high-sensitivity.md) — OOB
  Confirmation channel whose event contract is captured in the AsyncAPI spec
  and whose policy gate is covered by the Rego companion tests.
  See also: ADR-0011 `## More Information` backlinks this ADR.
* [0017-llm-as-composer-no-foreign-keys-between-secrets.md](0017-llm-as-composer-no-foreign-keys-between-secrets.md) — schema
  simplicity constraint (no foreign keys) that the CUE schemas already enforce
  and that the full-coverage validation lane keeps continuously verified.
  See also: ADR-0017 `## More Information` backlinks this ADR.

## Amendment — 2026-05-23 — Deployment Artifacts

A `deploy/` directory has been added to the repository root as a release
artifact tree. It contains OS-specific service descriptors and configuration
templates required for production installation of `merkle-agent`:

| File | Purpose |
|---|---|
| `deploy/systemd/merkle-agent.service` | Linux systemd unit (Type=notify, security-hardened) |
| `deploy/launchd/dev.fapp.merkle.plist` | macOS launchd agent plist |
| `deploy/windows/merkle-agent-service.xml` | WinSW service wrapper for Windows |
| `deploy/etc/merkle/config.toml.example` | Annotated configuration reference |
| `deploy/README.md` | Per-OS install instructions and troubleshooting |

The `deploy/` directory is **not** under `docs/arch/` and is **not** validated
by `spec validate --lane full`. These are deployment artifacts, not
architectural specifications. The `spec validate` contract (all 14 validators,
no skips) is not extended to cover deployment artifact linting. A future ADR
may introduce a separate `deploy validate` lane if machine-checkable deployment
contracts become necessary.

Cross-reference: [ADR-0023](0023-port-forward-via-ssh-tunnel.md) — the
port-forward implementation that `deploy/systemd/merkle-agent.service` enables
by specifying the runtime environment and required capabilities.
