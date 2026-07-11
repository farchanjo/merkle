---
id: 019f4f44-6a13-7b01-908f-8f94065b7c3c
number: 007
slug: allowlisted-spawn-proxy
status: implemented
created_at: 2026-07-11T03:41:51.507092Z
---
# Feature Specification: Allowlisted Spawn Proxy

## User Stories
- As an operator I want spawn with secret env injection for allowlisted binaries so automation works without 501.

## Functional Requirements
1. SpawnCommandCommand allows only a closed basename allowlist.
2. Decrypts first secret_handle into env var; runs argv; returns stdout/stderr/exit_code.
3. POST /v1/proxy/spawn wires to the command (not 501).
4. Non-allowlisted binaries audit deny and return policy denied.

## Security Requirements
- **Data sensitivity/classification.** Secret plaintext only in process env of child.
- **Authentication/authorization.** Unsealed Companion Socket; fail-closed allowlist.
- **Input validation.** Non-empty argv and env_var identifier; at least one secret handle.
- **Cryptography in transit/at rest.** DEK decrypt in agent only.
- **Logging/audit.** Spawn allow/deny without secret values.
- **Error-handling information exposure.** No secret bytes in errors.

## Acceptance Scenarios
Given Unsealed vault
When spawn with allowlisted binary and secret handle
Then response is not 501
When spawn with disallowed binary
Then policy denied

## Observability
- Log spawn program basename and exit_code only.

## Related
- Feature 007, ADR-0039

## Clarifications
