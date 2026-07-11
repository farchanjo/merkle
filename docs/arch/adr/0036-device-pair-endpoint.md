---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0036 — Wire Companion Device pair over Companion Socket

## Context and Problem Statement
CLI merkle device pair POSTs /v1/devices but the route was intentionally missing.

## Decision Drivers
- CLI already calls POST /v1/devices.
- PairDeviceCommand exists in application layer.
- Full attestation OOB UX can arrive later.

## Considered Options
1. Keep POST missing — rejected.
2. Wire POST with optional key generation (chosen).
3. Require full attestation chain now — deferred.

## Decision Outcome
Chosen option: "Wire POST with optional key generation", because it unblocks CLI and keeps attestation optional.

### Consequences
- Good: device pair works end-to-end.
- Bad: generated keypairs without hardware attestation are software-class only.

## Related
- Feature 004-device-pair-endpoint
- ADR-0020
