---
id: 019f4f42-d767-79f2-9317-9eab7fb97ce3
number: 005
slug: ssh-port-forward
status: implemented
created_at: 2026-07-11T03:40:08.42385Z
---
# Feature Specification: SSH Port Forward

## User Stories
- As an operator I want TCP port-forward over SSH so local services reach remote hosts via vault SSH keys.

## Functional Requirements
1. PortForwardCommand enforces slash_command (and oob_ack for high sensitivity).
2. Spawns ssh -N -L with key in 0600 tempfile; registers Child in active_port_forwards.
3. POST /v1/proxy/ssh/port-forward returns 200 with session_id and local_addr when ssh accepts the tunnel (not 501).
4. Failed immediate exit surfaces domain error; success audits PortForward allow.

## Security Requirements
- **Data sensitivity/classification.** SSH private key decrypted only in agent memory and 0600 tempfile.
- **Authentication/authorization.** Companion Socket peer-cred; Unsealed; ADR-0011 confirmation.
- **Input validation.** Non-zero local_port; non-empty target, remote_host, and key.
- **Cryptography in transit/at rest.** Key never on socket wire; tempfile unlinked after tunnel ends.
- **Logging/audit.** Audit PortForward allow or deny without key material.
- **Error-handling information exposure.** No key bytes in errors.

## Acceptance Scenarios
Given Unsealed vault and an SSH key secret
When POST port-forward with a valid target
Then the response is not HTTP 501 and includes session_id when the tunnel stays up

## Related
- ADR-0037, PortForwardCommand, Feature 005

## Clarifications

## Observability
- Log port_forward spawn and exit with session_id only.
- Metric later: port_forward_active gauge.

