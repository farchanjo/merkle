---
id: 019f4f47-be0e-7412-b4a3-e4175d0b5fdf
number: 008
slug: verified-oob-high-reveal
status: implemented
created_at: 2026-07-11T03:45:29.614571Z
archived: true
---
# Feature Specification: Verified OOB High Reveal

## User Stories
- As an operator I want High-sensitivity reveal to require a real OOB challenge so a forged oob_ack cannot decrypt secrets.

## Functional Requirements
1. When sensitivity meets oob_threshold or profile is Paranoid, dispatch OobChallenge via OobNotifier.
2. Await resolution; only Approved continues; timeout/deny audit Reveal deny.
3. Transport oob_ack boolean is never trusted as authorization.
4. When enrolled device has non-zero Ed25519 pubkey and resolution carries a signature, verify signature over request_nonce.
5. POST /v1/reveal no longer returns 501 for OOB-gated reveals; it runs the verified OOB path.
6. Low/medium reveals without OOB requirement remain slash_command-only.

## Security Requirements
- **Data sensitivity/classification.** Plaintext only after verified OOB + slash.
- **Authentication/authorization.** Slash from peer-cred path; OOB from notifier resolution.
- **Input validation.** Handle must exist; policy kill-switch honored.
- **Cryptography in transit/at rest.** AEAD decrypt after gates; optional Ed25519 OOB sig.
- **Logging/audit.** Reveal allow/deny without plaintext.
- **Error-handling information exposure.** Stable denial reasons only.

## Acceptance Scenarios
Given High secret and auto-approving OOB notifier
When reveal with slash_command true and oob_ack false
Then plaintext is returned

Given High secret and no OOB approval
When reveal with forged oob_ack true
Then reveal is denied

## Observability
- Log challenge_id on OOB approve/deny.

## Related
- reveal_with_oob.feature, ADR-0040, ADR-0011

## Clarifications
