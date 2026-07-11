# Implementation Plan: Corpus Health Green

## Goal

Make `speckit validate` report zero findings without waivers, raise governance
structure scores, eliminate orphan schema score gaps, and leave a recorded SDD
feature that explains the dual-tree control plane posture.

## Approach

1. Reshape CUE schemas for ddd-tactical and calisthenics compliance (parts,
   primitives as ValueObjects, AggregateRoot identity fields).
2. Complete operations, CLI surface, and SLO index required headings and path
   references that resolve on disk.
3. Index and cross-link all CUE files from domain docs and `schemas/README.md`.
4. Fix integration docs path-like backtick references.
5. Record acceptance via this feature and ADR-0033.

## Technical Design

- Dual tree retained: `docs/arch` technical SoT, `doc/arch` control plane +
  symlinks.
- No permanent `[[validate.waivers]]` for calisthenics.
- Schema fragmentation accepted as the cost of native validators.

## Security

Docs and CUE only. No secret material in artifacts. Validators remain fail-closed.

## Observability

Gates: `speckit validate`, `speckit check`, `speckit status` health components.

## Rollout

Already applied on the feature branch; merge to main after validate stays green.

## Tasks mapping

See `tasks.md` for ordered work items (all complete for this meta-feature).
