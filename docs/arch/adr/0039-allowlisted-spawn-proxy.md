---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0039 — Allowlisted spawn proxy with secret env injection

## Context and Problem Statement
POST /v1/proxy/spawn returned 501; unrestricted process spawn is unsafe.

## Decision Drivers
- Fail-closed binary allowlist.
- Secret injection without disk writes.
- Audit every attempt.

## Considered Options
1. Keep 501 forever — rejected.
2. Open spawn any binary — rejected.
3. Closed allowlist spawn (chosen).

## Decision Outcome
Chosen option: "Closed allowlist spawn", because it unblocks common tools with bounded risk.

### Consequences
- Good: curl/git/ssh/jq automation works.
- Bad: custom binaries require allowlist updates.

## Related
- Feature 007
