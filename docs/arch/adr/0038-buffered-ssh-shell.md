---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0038 — Buffered SSH shell over Companion Socket

## Context and Problem Statement
POST /v1/proxy/ssh/shell returned 501 while SshShellCommand already implements buffered remote shell.

## Decision Drivers
- Interactive PTY is expensive and unsafe to rush.
- Buffered shell unblocks operator workflows today.

## Considered Options
1. Keep 501 until streaming PTY — rejected for product gap.
2. Wire buffered SshShellCommand (chosen).
3. Full PTY WebSocket — deferred.

## Decision Outcome
Chosen option: "Wire buffered SshShellCommand", because it reuses ssh_exec security.

### Consequences
- Good: shell endpoint returns real output.
- Bad: not interactive; clients must send full command each time.

## Related
- Feature 006-buffered-ssh-shell
