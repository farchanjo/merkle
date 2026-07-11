---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0042 — Session unbind close clears ephemeral state

## Context and Problem Statement
`DELETE /v1/sessions/{id}` must not leave use-tokens, secret-bearing tempfiles, or
SSH port-forward children alive after an MCP client disconnects. Namespace
bindings are durable (ADR-0026) and must survive session close.

## Decision Drivers
- Companion Socket is the sole inbound surface; close is HTTP DELETE on sessions.
- Tempfiles may hold secret material on disk — unlink on close.
- Bindings must remain persistent so re-open does not re-pair the namespace.

## Considered Options
1. Full unbind (drop namespace binding) — rejected (breaks ADR-0026).
2. No-op close with closed=true only — rejected (token/tunnel leak).
3. Clear in-memory hygiene only (tokens, tempfiles, forwards) — chosen.

## Decision Outcome
Chosen option: "close_session_state clears tokens/tempfiles/forwards", because it
matches session hygiene without destroying durable namespace bindings.

### Consequences
- Good: DELETE returns counts of tokens revoked and tempfiles cleaned.
- Bad: multi-session token maps are cleared globally in the 1:1 agent phase
  (acceptable while one client dominates the agent process).

## Related
- Feature 010, ADR-0026
