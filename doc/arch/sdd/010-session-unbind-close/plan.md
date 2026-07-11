# Plan: Session Unbind Close

## Approach
Implement `AppContext::close_session_state` to drain use-tokens and tempfiles and
kill port-forward children, then wire `DELETE /v1/sessions/{id}` to call it and
return `CloseSessionResponse` counts.

## Architecture
- Application: `context.rs` hygiene helper.
- Adapter: `handlers/sessions.rs` HTTP DELETE.
- Contract: existing `CloseSessionResponse` fields.

## Out of scope
- Per-session token maps (global clear acceptable in 1:1 phase).
- Namespace unbind.
