---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0043 — Enroll passphrase fallback at vault init

## Context and Problem Statement
Feature 009 added Argon2id passphrase unseal, but operators still needed a
separate enroll step after init. Init should optionally wrap the Master Key under
the operator passphrase so first unseal can use passphrase without keychain.

## Decision Drivers
- Reuse `enroll_passphrase_fallback` from Feature 009 / ADR-0041.
- Do not fail the init ceremony if enroll fails (non-fatal warn).
- Support `InitVaultCommand.passphrase` and env `MERKLE_MASTER_PASSPHRASE`.

## Considered Options
1. Separate post-init enroll-only API — deferred (still available via code path).
2. Mandatory passphrase at init — rejected (keychain-only operators).
3. Optional enroll at end of init (chosen).

## Decision Outcome
Chosen option: "Optional passphrase enroll after successful init audit", because
it keeps init backward compatible and wires enroll into the ceremony once.

### Consequences
- Good: one command path for new vaults with passphrase recovery.
- Bad: enroll errors are logged but do not fail init (operator may miss warn).

## Related
- Feature 011, ADR-0041, ADR-0005
