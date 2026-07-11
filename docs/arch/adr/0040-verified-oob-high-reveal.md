---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0040 — Verified OOB path for high-sensitivity reveal

## Context and Problem Statement
High-sensitivity reveal returned 501 because transport oob_ack is forgeable and
the agent did not dispatch a real OOB challenge.

## Decision Drivers
- MERK-001: LLM cannot forge slash; oob_ack alone is not a proof.
- Terminal/desktop OOB notifiers already implement dispatch/await.
- Hardware devices may sign request_nonce.

## Considered Options
1. Keep 501 forever — rejected.
2. Trust transport oob_ack — rejected.
3. Dispatch real challenge and set oob_ack only after Approved (chosen).

## Decision Outcome
Chosen option: "Dispatch real challenge", because it uses existing OobNotifier
and fails closed on timeout/deny.

### Consequences
- Good: High reveal works with operator OOB.
- Bad: headless CI must use fixture/auto-approve notifiers.

## Related
- Feature 008, ADR-0011, ADR-0019
