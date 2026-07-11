---
id: 019f4f3e-5eb2-755f-a24c-aadbabea146b
number: 003
slug: disaster-recovery-path
status: implemented
created_at: 2026-07-11T03:35:15.404064Z
---
# Feature Specification: Disaster Recovery Path

## User Stories
- As an operator who lost the Master Key I want to recover from a dual-recipient Backup using the Recovery Key so the vault is unsealed with a fresh Master Key and secrets restored.

## Functional Requirements
1. New dual-recipient backups (v2) embed the recovery-wrapped Vault Root Key age ciphertext plus secrets.
2. DisasterRecoverCommand accepts recovery age identity and backup path; verifies recovery fingerprint against vault recovery recipient before decrypt.
3. On match, decrypts backup, unwraps VRK, generates new Master Key, dual-wraps VRK into keychain, rehydrates secrets, unseals, audits op=disaster_recovery allow.
4. On fingerprint mismatch, deny with recovery_key_fingerprint_mismatch and no mutation of vault secrets.
5. Legacy v1 backups remain restoreable via Master Key path but reject disaster recovery with a clear domain error.

## Security Requirements
- **Data sensitivity/classification.** Recovery identity and VRK are highest sensitivity; never logged.
- **Authentication/authorization.** Operator must possess Recovery Key; Companion Socket optional later.
- **Input validation.** Empty identity/path rejected; non-v2 backups rejected for DR.
- **Cryptography in transit/at rest.** Age dual-recipient backup; AEAD master wrap; age recovery wrap.
- **Logging/audit.** Audit DisasterRecovery allow/deny without key material.
- **Error-handling information exposure.** Stable error codes only.

## Acceptance Scenarios
Given a v2 backup and matching Recovery Key
When disaster recover runs
Then secrets are restored, vault is Unsealed, new master is in keychain

Given a Recovery Key that does not match the vault recovery recipient
When disaster recover runs
Then error recovery_key_fingerprint_mismatch and secrets are unchanged

## Observability
- Log disaster_recover start/complete with secrets_restored count only.
- Metric later: disaster_recover_total{outcome}.

## Related
- Gherkin disaster_recovery.feature
- ADR-0035

## Clarifications
