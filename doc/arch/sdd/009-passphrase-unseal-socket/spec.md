---
id: 019f4f49-a2b6-7872-9d0b-c9f77fb96d68
number: 009
slug: passphrase-unseal-socket
status: implemented
created_at: 2026-07-11T03:47:33.686262Z
---
# Feature Specification: Passphrase Unseal Socket

## User Stories
- As an operator I want to unseal via Argon2id passphrase over Companion Socket when the OS keychain Master Key is unavailable.

## Functional Requirements
1. UnsealRequest carries optional passphrase field.
2. UnsealVaultCommand accepts passphrase; when set, loads Argon2id params + master wrap from keychain and derives Master Key.
3. enroll_passphrase_fallback stores wrap after Master Key is known.
4. Wrong passphrase yields unseal_authentication_failed / PolicyDenied without unsealing.
5. CLI merkle unseal --passphrase POSTs passphrase to agent (no local ignore warning).
6. UnsealResponse.method reports keychain vs argon2id_passphrase.

## Security Requirements
- **Data sensitivity/classification.** Passphrase only in transit over local UDS; not logged.
- **Authentication/authorization.** Peer-cred socket; Argon2id floor m>=65536 t>=3 p>=1.
- **Input validation.** Empty passphrase rejected; missing enroll returns clear error.
- **Cryptography in transit/at rest.** Argon2id + AEAD wrap of master; VRK unwrap unchanged.
- **Logging/audit.** Unseal allow without passphrase material.
- **Error-handling information exposure.** No salt or wrap bytes in client errors.

## Acceptance Scenarios
Given enrolled passphrase wrap
When unseal with correct passphrase and no keychain master
Then vault Unsealed with method argon2id_passphrase

Given wrong passphrase
When unseal
Then authentication fails and vault stays sealed

## Observability
- Log unseal method enum only.

## Related
- ADR-0041, ADR-0005, unseal.feature

## Clarifications
