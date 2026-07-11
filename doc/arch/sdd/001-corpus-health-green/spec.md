---
id: 019f4f16-5e9b-71ca-a311-3991d3f2dd85
number: 001
slug: corpus-health-green
status: implemented
created_at: 2026-07-11T00:00:00Z
archived: true
---
# Feature Specification: Corpus Health Green

Feature: 001-corpus-health-green
Created: 2026-07-11

## User Stories

- As a Merkle maintainer I want the committed arch corpus to pass `speckit validate` with zero findings so that CI and local gates stay trustworthy.
- As an agent operator I want project health and governance docs complete so that onboarding maps match the control plane.

## Functional Requirements

1. The repository root control plane under `doc/arch` remains dual-linked to `docs/arch` technical corpus via symlinks.
2. CUE schemas under `docs/arch/schemas` satisfy native ddd-tactical and calisthenics validators without validate.waivers.
3. Governance docs (operations, SLO index, CLI surface, constitution, quality, privacy) meet required section anchors.
4. Integration docs do not contain dead path-like backtick references that fail groundedness scoring.
5. `speckit validate` exits 0 with zero findings on a clean tree.
6. `speckit check` accepts Angular subjects of length at most 72 characters.

## Security Requirements

- **Data sensitivity/classification.** Not applicable — this feature edits documentation and CUE contracts only; no secret plaintext is processed.
- **Authentication/authorization.** Not applicable — no new authenticated surface.
- **Input validation.** Speckit validators bound untrusted corpus text; malformed CUE/YAML fails closed at validate time.
- **Cryptography in transit/at rest.** Not applicable — no new crypto surface.
- **Logging/audit.** Not applicable — docs-only; no new audit ops.
- **Error-handling information exposure.** Validator findings must not embed secret material; they report paths and rule ids only.

## Acceptance Scenarios

Given a clean checkout of main with the dual-tree corpus
When an operator runs `speckit validate`
Then the command exits 0 and reports zero findings

Given the governance and schema index documents
When an operator runs `speckit spec score`
Then governance docs score without missing required structure anchors for operations, CLI surface, and SLO index

Given commit history on main
When an operator runs `speckit check`
Then git prerequisites pass including Angular subject length

## Observability

- Metric: none new — validate/check are offline gates.
- Log: `speckit validate` human and `--json` output for CI.
- Trace: not applicable.
- Operator signal: `speckit status` project health components `validateCleanliness` and `governanceDocs`.

## Schema contracts

- [`docs/arch/schemas/corpus-health-green.cue`](../../schemas/corpus-health-green.cue)
- Schema index: [`docs/arch/schemas/README.md`](../../schemas/README.md)
