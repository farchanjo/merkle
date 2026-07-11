---
id: 019f4f3f-72a8-71d0-ae00-b4db6b954b4b
number: 004
slug: device-pair-endpoint
status: implemented
created_at: 2026-07-11T03:36:26.024614Z
archived: true
---
# Feature Specification: Device Pair Endpoint

## User Stories
- As an operator I want POST /v1/devices so merkle device pair enrolls a companion device without a 404.

## Functional Requirements
1. POST /v1/devices enrolls a CompanionDevice and returns 201 with device_id.
2. Accept optional class and optional ed25519/x25519 pubkeys (hex); generate keys when absent.
3. Require Unsealed vault; audit enrollment.
4. GET list and DELETE revoke remain unchanged.

## Security Requirements
- **Data sensitivity/classification.** Device public keys only; no private keys returned.
- **Authentication/authorization.** Peer-cred Companion Socket; Unsealed required.
- **Input validation.** Hex pubkeys 64 chars when provided.
- **Cryptography in transit/at rest.** Keys stored as public material only.
- **Logging/audit.** Audit Put/enroll without private material.
- **Error-handling information exposure.** Stable problem types.

## Acceptance Scenarios
Given Unsealed vault
When POST /v1/devices with class software
Then 201 and device appears in GET /v1/devices

## Observability
- Log pair_device with device_id.

## Related
- ADR-0036, PairDeviceCommand, ADR-0020

## Clarifications
