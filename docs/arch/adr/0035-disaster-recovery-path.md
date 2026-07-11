---
status: accepted
date: 2026-07-11
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0035 — Disaster recovery via Recovery Key and backup v2

## Context and Problem Statement
Losing the OS keychain Master Key bricks unseal. Dual-recipient backups and
recovery-wrapped VRK exist, but no end-to-end disaster recovery command re-wraps
under a new Master Key and restores secrets.

## Decision Drivers
- Recovery Key is the only operator-held secret for Master Key loss.
- Backups must carry recovery-wrapped VRK without breaking v1 decrypt.
- Fail closed on fingerprint mismatch.

## Considered Options
1. Require separate VRK blob file — rejected because operator UX is worse.
2. Embed recovery-wrapped VRK in backup v2 — chosen.
3. Re-init empty vault only — rejected because it loses secrets.

## Decision Outcome
Chosen option: "Embed recovery-wrapped VRK in backup v2", because it reuses
init dual-wrap and dual-recipient age backups.

### Consequences
- Good: single backup file enables full recovery ceremony.
- Bad: older v1 backups cannot disaster-recover VRK though Master Key restore still works.

## Related
- Feature 003-disaster-recovery-path
- ADR-0021 init dual-wrap
- ADR-0034 backup restore path
