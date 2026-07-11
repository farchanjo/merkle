---
id: 019f4f43-4885-7910-b273-4736b3147ee1
number: 006
slug: buffered-ssh-shell
status: implemented
created_at: 2026-07-11T03:40:37.381282Z
archived: true
---
# Feature Specification: Buffered SSH Shell

## User Stories
- As an operator I want a non-PTY remote shell over SSH using vault keys so I can run remote commands without 501.

## Functional Requirements
1. POST /v1/proxy/ssh/shell decrypts key_handle and runs SshShellCommand (buffered).
2. Optional command field; default /bin/sh -l.
3. Response carries stdout, stderr, exit_code — not a streaming session_id.
4. Full interactive PTY remains out of scope.

## Security Requirements
- **Data sensitivity/classification.** SSH key plaintext only in agent.
- **Authentication/authorization.** Unsealed Companion Socket peer-cred.
- **Input validation.** Required namespace_id, key_handle, target.
- **Cryptography in transit/at rest.** Same tempfile path as ssh_exec via ExternalServices.
- **Logging/audit.** Audit ssh_exec allow.
- **Error-handling information exposure.** No key material in errors.

## Acceptance Scenarios
Given Unsealed vault
When POST /v1/proxy/ssh/shell with valid key
Then response is not 501 and includes exit_code

## Observability
- Log ssh_shell with target and exit_code.

## Related
- Feature 006, SshShellCommand, ADR-0038

## Clarifications
