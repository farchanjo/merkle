---
id: 019f4f6c-967b-73c2-b800-4b8a7c3f1329
number: 012
slug: crypto-sign-rsa-sha256
status: implemented
created_at: 2026-07-11T04:25:44.315666Z
---
# Feature Specification: Crypto Sign RSA-SHA256

## User Stories
- As an agent caller I want RSA-SHA256 signatures from vault-held private keys so legacy consumers can verify without exporting keys.

## Functional Requirements
1. `CryptoSignAlgorithm::RsaSha256` signs with PKCS#1 v1.5 + SHA-256.
2. Key bytes accept PEM or DER PKCS#8 / PKCS#1 RSA private keys.
3. Companion Socket maps algorithm string `rsa-sha256` (no longer 501).
4. Ed25519 path remains unchanged (32-byte seed).
5. Audit `op=crypto_sign` on success.

## Security Requirements
- **Data sensitivity/classification.** Private key decrypted in memory for sign only; not returned to client.
- **Authentication/authorization.** Requires unsealed vault and existing secret access path.
- **Input validation.** Malformed keys → InvalidInput; wrong length Ed25519 unchanged.
- **Cryptography in transit/at rest.** AEAD-decrypt key secret then RSA sign; no new key storage format.
- **Logging/audit.** Algorithm and handle only; no key or message dump.
- **Error-handling information exposure.** Parse errors as short InvalidInput strings without key bytes.

## Acceptance Scenarios
Given RSA PEM key secret in vault
When crypto-sign with RsaSha256
Then signature_hex is returned and audit allows

Given garbage key bytes
When RsaSha256 sign is requested
Then InvalidInput without signature

## Observability
- Log key_handle and algorithm on load and success.

## Related
- ADR-0044, crypto-sign-rsa-sha256.feature

## Clarifications
