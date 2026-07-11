# Plan: Init Passphrase Enroll

## Approach
After durable init audit, optionally call existing `enroll_passphrase_fallback`
using command field or `MERKLE_MASTER_PASSPHRASE`.

## Architecture
- Application: `init_vault.rs` post-audit enroll hook.
- Reuse: `unseal_vault::enroll_passphrase_fallback`.

## Out of scope
- Separate public enroll HTTP endpoint (code path only).
