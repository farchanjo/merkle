---
id: 019f4f6c-9742-7bd1-980b-617b28735f9a
number: 013
slug: audit-remote-hmac-webhook
status: implemented
created_at: 2026-07-11T04:25:44.514815Z
---
# Feature Specification: Audit Remote HMAC Webhook

## User Stories
- As a compliance operator I want durable audit entries POSTed to a remote URL with request HMAC so SIEM can verify integrity without blocking the vault.

## Functional Requirements
1. `AppContext.audit_webhook_url` from `MERKLE_AUDIT_WEBHOOK_URL` or `set_audit_webhook_url`.
2. After successful persist in `audit_commit`, call `fire_audit_webhook`.
3. POST JSON body: seq, op, outcome, current_hash, hmac (entry chain fields).
4. Header `X-Merkle-Audit-HMAC` = HMAC over body bytes with audit HMAC key.
5. Delivery is fire-and-forget (`tokio::spawn`); failures warn only.
6. Missing URL → no network.

## Security Requirements
- **Data sensitivity/classification.** Remote body is audit metadata (op/outcome/hashes), not secret payloads.
- **Authentication/authorization.** Request MAC with vault audit HMAC key; receiver must share or verify offline.
- **Input validation.** URL from env/config; empty filtered to None.
- **Cryptography in transit/at rest.** Local chain unchanged; request-level HMAC; TLS left to ExternalServices (pin deferred).
- **Logging/audit.** Local commit remains source of truth; warn on delivery failure without body dump.
- **Error-handling information exposure.** Webhook errors do not fail audit_commit.

## Acceptance Scenarios
Given webhook URL configured
When audit_commit succeeds
Then POST is attempted with X-Merkle-Audit-HMAC

Given no URL
When audit_commit succeeds
Then no HTTP request and local audit is durable

## Observability
- `tracing::warn` on delivery failure; no metric required in this feature.

## Related
- ADR-0045, audit-remote-hmac-webhook.feature

## Clarifications
