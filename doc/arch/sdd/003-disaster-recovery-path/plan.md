# Plan: Disaster Recovery Path

## Goal
Enable Master Key loss recovery via Recovery Key and dual-recipient backup v2.

## Approach
1. Backup payload v2 embeds keychain vrk-recovery-v1 age blob plus secrets.
2. DisasterRecoverCommand verifies fingerprint, unwraps VRK, re-wraps under new Master Key, rehydrates secrets, unseals.
3. Integration test covers happy path.

## Crates
- merkle-application: backup_payload, trigger_backup, disaster_recover
- Tests: use_cases disaster_recover_rewrapping_master_from_v2_backup
