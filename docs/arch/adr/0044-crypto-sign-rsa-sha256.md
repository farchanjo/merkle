---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0044 — RSA PKCS#1 v1.5 SHA-256 crypto-sign

## Context and Problem Statement
`CryptoSignCommand` and Companion Socket proxy only supported Ed25519; RSA keys
stored as secrets returned 501 or InvalidInput. External systems often require
RSA-SHA256 signatures (JWT, package signing, legacy APIs).

## Decision Drivers
- Keep Ed25519 path unchanged (32-byte seed).
- Accept PEM/DER PKCS#8 or PKCS#1 RSA private keys from vault secret bytes.
- Use RSA PKCS#1 v1.5 + SHA-256 via the `rsa` crate (SigningKey\<Sha256\>).
- Audit as `op=crypto_sign` without logging key material.

## Considered Options
1. Leave RSA as 501 Not Implemented — rejected (product gap).
2. PSS-only RSA — deferred (callers expect PKCS#1 v1.5).
3. PKCS#1 v1.5 SHA-256 with PEM/DER parse (chosen).

## Decision Outcome
Chosen option: "RsaSha256 algorithm enum + sign_rsa_sha256 helper", because it
unblocks vault-held RSA keys without changing the Ed25519 contract.

### Consequences
- Good: socket maps `rsa-sha256` to `CryptoSignAlgorithm::RsaSha256`.
- Bad: PKCS#1 v1.5 is not PSS; callers that need PSS still need a later ADR.

## Related
- Feature 012
