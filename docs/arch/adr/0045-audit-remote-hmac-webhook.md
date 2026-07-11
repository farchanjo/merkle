---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0045 — Fire-and-forget remote audit HMAC webhook

## Context and Problem Statement
Local audit chain is durable, but SIEM / compliance sinks need a remote POST of
each committed entry with integrity. Delivery must not block or fail the local
audit commit path.

## Decision Drivers
- Hook after successful `audit_commit` persistence only.
- Config via `MERKLE_AUDIT_WEBHOOK_URL` / `AppContext::set_audit_webhook_url`.
- Request integrity: `X-Merkle-Audit-HMAC` over JSON body using audit HMAC key.
- Use `ExternalServices::http_request` (hexagonal outbound port).
- Fire-and-forget (`tokio::spawn`); warn on delivery failure.

## Considered Options
1. Synchronous webhook inside audit_commit — rejected (latency + failure coupling).
2. Outbox table + worker — deferred (queue depth / TLS pin later).
3. Best-effort spawn after durable commit (chosen).

## Decision Outcome
Chosen option: "fire_audit_webhook after persist, non-blocking", because local
audit remains source of truth and remote delivery is optional telemetry.

### Consequences
- Good: zero config = no network; webhook optional.
- Bad: no retry queue, no TLS pin in this ADR (follow-up).

## Related
- Feature 013
