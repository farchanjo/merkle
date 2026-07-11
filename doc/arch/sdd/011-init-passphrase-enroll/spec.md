---
id: 019f4f6c-9522-7d01-8fd9-214c0788f976
number: 011
slug: init-passphrase-enroll
status: implemented
created_at: 2026-07-11T04:25:43.970701Z
archived: true
---
# Feature Specification: Init Passphrase Enroll

## User Stories
- As an operator I want vault init to optionally enroll Argon2id passphrase wrap so I can unseal without a separate enroll step.

## Functional Requirements
1. `InitVaultCommand.passphrase: Option<String>` enrolls fallback after successful init audit.
2. When command passphrase is absent, read `MERKLE_MASTER_PASSPHRASE` if non-empty.
3. Call `enroll_passphrase_fallback` with Master Key bytes and passphrase.
4. Enroll failure is non-fatal (warn log); init still succeeds.
5. Empty passphrase does not enroll.

## Security Requirements
- **Data sensitivity/classification.** Passphrase in process memory only; never logged.
- **Authentication/authorization.** Init remains local peer-cred / agent process ceremony.
- **Input validation.** Empty string filtered; enroll rejects empty passphrase.
- **Cryptography in transit/at rest.** Argon2id + AEAD wrap per ADR-0005 / ADR-0041.
- **Logging/audit.** Info on success enroll; warn on failure without passphrase material.
- **Error-handling information exposure.** Enroll errors stringified without salt/wrap bytes in client init response.

## Acceptance Scenarios
Given init with passphrase set
When ceremony completes
Then passphrase wrap accounts exist in keychain

Given init without passphrase
When ceremony completes
Then no passphrase wrap is enrolled

## Observability
- Log `init_vault: passphrase fallback enrolled` or non-fatal failure.

## Related
- ADR-0043, ADR-0041, ADR-0005, init-passphrase-enroll.feature

## Clarifications
