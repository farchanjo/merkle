---
id: 019f4f68-8646-7702-bd5f-6ec3616aef37
number: 010
slug: session-unbind-close
status: implemented
created_at: 2026-07-11T04:21:18.022973Z
---
# Feature Specification: Session Unbind Close

## User Stories
- As an MCP client I want DELETE /v1/sessions to clear in-memory session state so tokens and tunnels do not leak.

## Functional Requirements
1. `close_session` clears use-tokens, unlinks tempfiles, kills port-forwards.
2. Namespace bindings remain persistent (ADR-0026).
3. Response reports `closed=true` and counts of tokens revoked and tempfiles cleaned.
4. Implementation lives in `AppContext::close_session_state` and the Companion Socket sessions handler.

## Security Requirements
- **Data sensitivity/classification.** Deletes local secret-bearing tempfiles; does not log secret contents.
- **Authentication/authorization.** Companion Socket peer-cred only.
- **Input validation.** Session UUID path param; invalid UUID falls back to a fresh UuidV7 (no-op clean).
- **Cryptography in transit/at rest.** N/A — local process state only.
- **Logging/audit.** Optional future; counts only in response body.
- **Error-handling information exposure.** Always 200 with closed=true on the success path.

## Acceptance Scenarios
Given an open session with tokens
When DELETE /v1/sessions/{id}
Then closed is true and token count decreases

Given a bound namespace
When the session is closed
Then the namespace binding remains durable

## Observability
- Log session close counts when instrumented; response body carries revoke/cleanup counts.

## Related
- ADR-0042, ADR-0026, session-unbind-close.feature

## Clarifications
