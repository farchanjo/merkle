---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0037 — Enable SSH port-forward with confirmation and tempfile keys

## Context and Problem Statement
POST /v1/proxy/ssh/port-forward returned 501 while the product surface advertised the tool.

## Decision Drivers
- ADR-0011 confirmation is required.
- Key material must use a 0600 tempfile like ssh_exec.
- Child processes must be tracked for lifecycle cleanup.

## Considered Options
1. Keep 501 — rejected.
2. Enable with slash confirmation and tempfile — chosen.
3. Full multiplexed forwarder — deferred.

## Decision Outcome
Chosen option: "Enable with slash confirmation and tempfile", because it matches the ssh_exec security posture.

### Consequences
- Good: product port-forward works for valid SSH targets.
- Bad: multi-tunnel management remains a simple in-memory map.

## Related
- Feature 005-ssh-port-forward
- ADR-0023
