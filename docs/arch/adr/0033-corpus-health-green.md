---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0033 — Corpus health green as a first-class control-plane gate

## Context and Problem Statement

After dual-tree speckit integration, validate could be green only via large
waiver sets, while project health stayed low because waived findings still
zeroed `validateCleanliness` and missing structure anchors depressed
governance scores. Maintainers need a durable decision that the arch corpus
must pass native validators without waivers and that dual-tree docs remain
linked.

## Decision Drivers

- Speckit errors cannot be waived; warnings that block health must be fixed.
- Dual tree (`docs/arch` contract + `doc/arch` control plane) must stay one corpus via symlinks.
- CUE calisthenics and ddd-tactical rules are enforced, not disabled.

## Considered Options

- Option A: Keep permanent `[[validate.waivers]]` for calisthenics.
- Option B: Drop dual-tree and re-root everything under `doc/arch` immediately.
- Option C: Fix schemas and governance docs to zero findings and raise scores.

## Decision Outcome

Chosen option: "Option C: Fix schemas and governance docs to zero findings",
because it preserves the technical corpus location expected by BDD and
Makefile history while making the control plane honest.

### Consequences

- Good: `speckit validate` exits 0 with zero findings without waivers.
- Good: schema index and domain links prevent orphan-score collapse.
- Bad: CUE files are more fragmented (parts/primitives) for calisthenics compliance.
- Bad: full re-root of `docs/arch` to `doc/arch` remains a later cutover.

## Related

- [Product overview](../functional/product-overview.md)
- [Schema index](../schemas/README.md)
- Feature `001-corpus-health-green`
