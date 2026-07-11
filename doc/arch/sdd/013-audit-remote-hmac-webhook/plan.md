# Plan: Audit Remote HMAC Webhook

## Approach
Add optional URL on AppContext; after durable audit persist, spawn a POST via
ExternalServices with body HMAC header. Never fail the local commit path.

## Architecture
- Application: `context.rs` URL field; `unseal_vault::fire_audit_webhook`.
- Port: existing `ExternalServices::http_request`.

## Out of scope
- Retry queue, TLS pin, delivery metrics (follow-up).
