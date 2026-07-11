---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0041 — Passphrase unseal over Companion Socket

## Context and Problem Statement
CLI unseal --passphrase ignored the passphrase because UnsealRequest had no fields
and the agent only read the Master Key from the keychain.

## Decision Drivers
- ADR-0005 Argon2id floor and salt in durable storage (keychain params record).
- Passphrase must not log; UDS peer-cred only.
- Must not change VRK unwrap format.

## Considered Options
1. Keep keychain-only unseal — rejected.
2. Passphrase derives Master Key directly replacing wrap — rejected (breaks random master).
3. Enroll AEAD wrap of Master under Argon2id-derived key (chosen).

## Decision Outcome
Chosen option: "Enroll AEAD wrap of Master under Argon2id key", because it keeps
random master generation while enabling passphrase recovery of the same Master Key.

### Consequences
- Good: CLI passphrase path works end-to-end.
- Bad: operators must enroll wrap once (init/enroll helper).

## Related
- Feature 009, ADR-0005
