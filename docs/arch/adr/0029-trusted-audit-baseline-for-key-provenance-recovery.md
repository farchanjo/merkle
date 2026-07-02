---
status: accepted
date: 2026-07-01
deciders: farchanjo
consulted: []
informed: []
---

# ADR-0029 — Trusted audit baseline (checkpoint) for key-provenance recovery

## Context and Problem Statement

The audit hash chain authenticates every entry with an HMAC derived from the
Vault Root Key (`derive_audit_hmac_key(vrk_bytes)`, ADR-0009 / BUG-05). The
derivation is a deterministic pure function of `vrk_bytes`, so a stable VRK
yields a stable key and `ChainVerifier::verify_full` passes end to end.

A live dogfood vault surfaced a failure mode the current model cannot recover
from. During early operation the daemon briefly loaded a **different VRK** from
a different keystore backend (the `auto` OS-keychain probe transiently
succeeded, then the daemon settled on the file backend — see ADR-0015 and the
`build_keychain` fallback in `bin/merkle-agent/src/run.rs`). The audit entries
written during that window carry HMAC tags computed under a key that the vault
no longer holds. Result: `verify_full` reports `HmacMismatch` at the first
poisoned entry and halts, even though:

- the BLAKE3 hash chain (links + `current_hash`) is fully intact — no content
  was mutated, reordered, inserted, or truncated;
- the genesis entry and the entire tail after the poisoned window verify
  cleanly under the current key;
- every secret decrypts normally (the secret-encryption VRK path was
  unaffected).

This is a **key-provenance** failure, not tampering. Two constraints block the
obvious repairs:

1. **In-place HMAC repair is impossible.** `audit_entries` is append-only,
   enforced by SQL triggers (`001_initial.sql`) — historical rows cannot be
   `UPDATE`d to re-sign their HMAC tags under the current key.
2. **Silent acceptance is unacceptable.** Downgrading `verify_full` to
   hash-only, or ignoring the poisoned prefix without an authenticated marker,
   would discard the very tamper-evidence guarantee the chain exists to provide.

We need a way to re-anchor trust from a known-good point forward **without**
deleting history, forging tamper-evidence for the poisoned prefix, or weakening
verification of the tail.

## Decision Drivers

- **Honesty over green ticks.** A recovered chain must not claim to authenticate
  entries it cannot authenticate. The poisoned prefix must be visibly
  quarantined, never silently re-signed.
- **No destructive DB writes.** Append-only discipline (ADR-0009) stays intact;
  recovery adds a record, it does not rewrite history.
- **Full forward tamper-evidence.** Every entry from the anchor onward keeps
  HMAC + head-commitment verification exactly as before.
- **Structural integrity everywhere.** The hash chain must still be walked over
  the *entire* log so any content mutation — including below the anchor — is
  detected.
- **Operator-gated, not LLM-reachable.** Re-anchoring is an integrity-affecting
  administrative action. It must require operator confirmation and MUST NOT be
  exposed as an MCP tool (MERK-001).

## Considered Options

1. **Offline re-sign of poisoned rows.** A sealed maintenance command
   recomputes each poisoned entry's HMAC under the current key via a migration
   that bypasses the append-only trigger. Rejected: fabricates tamper-evidence
   for history the operator cannot independently vouch for, and mutates
   append-only rows — a direct violation of ADR-0009.
2. **Fresh-vault migration.** Export all secrets, `merkle init` a clean vault,
   re-import. Rejected for recovery: discards all audit history and requires a
   full-vault exporter that does not yet exist; disproportionate to a
   prefix-only provenance issue.
3. **Trusted audit baseline (checkpoint).** Persist an operator-pinned,
   key-authenticated checkpoint `(baseline_seq, baseline_hash, …)`; verify
   structural integrity across the whole chain but require HMAC authenticity
   only from the baseline forward. Chosen.

## Decision Outcome

Chosen: **option 3 — a trusted audit baseline**.

A new value object `AuditBaseline` (bounded context: Audit & Compliance)
records a checkpoint:

- `baseline_seq` — sequence number of the anchor entry;
- `baseline_id` — identity (UUIDv7) of the anchor entry;
- `baseline_hash` — `current_hash` of the anchor entry (which, via the hash
  chain, commits to the entire prefix beneath it);
- `entry_count` — number of entries the chain commits to at pin time;
- `reason` — free-form operator note (why the baseline was pinned);
- `created_at` — RFC 3339 UTC timestamp;
- `hmac` — `BLAKE3_keyed(key, DOMAIN || baseline_hash || baseline_seq ||
  baseline_id || entry_count)` under the **current** audit HMAC key, with a
  distinct domain separator (`b"merkle audit baseline v1"`) so a `PinnedHead`
  MAC can never be replayed as a baseline MAC.

`ChainVerifier::verify_from_baseline(log, pinned_head, baseline, key)`:

1. Requires a key (baseline verification is keyed-only); a missing/short key is
   `HmacKeyUnavailable`.
2. Authenticates the baseline MAC under the current key → `BaselineMacMismatch`
   on failure. This proves the operator pinned this exact `(seq, hash)` under
   the real key.
3. Enforces the genesis anchor and walks **every** entry from genesis doing
   link + `current_hash` recomputation (structural integrity for the whole
   log, so tamper below the baseline is still caught).
4. Verifies the HMAC tag **only** for entries with `seq >= baseline_seq`;
   entries below the baseline are counted as `quarantined_below` and their tags
   are not examined.
5. Confirms the anchor entry exists at `baseline_seq` with `current_hash ==
   baseline_hash` → `BaselineEntryMissing` otherwise.
6. Runs the existing head-commitment check against `PinnedHead` under the key.
7. On success returns `Intact` with `baseline_seq: Some(_)` and
   `quarantined_below` populated.

When a baseline is present, `VerifyChainQuery` and the `doctor`
`audit_chain_integrity` check call `verify_from_baseline`; otherwise they call
`verify_full` unchanged. A vault with no provenance incident never pins a
baseline and behaves exactly as before.

Pinning a baseline is a new application command
(`SetAuditBaselineCommand`) exposed **only** over the Companion Socket
(`POST /audit/rebaseline`) and the operator CLI (`merkle audit rebaseline`,
TTY-confirmed). It is audited as `AuditOp::Rebaseline` (variant count 32 → 33).
It is **not** an MCP tool.

### Consequences

- ✅ A vault that survived a key-provenance incident can return to a verifiable
  state without deleting or forging history.
- ✅ The poisoned prefix is explicitly quarantined and reported
  (`quarantined_below`), never silently accepted.
- ✅ Structural (hash-chain) integrity is still verified across the whole log,
  so content tampering below the baseline is still detected.
- ✅ Forward HMAC + head-commitment tamper-evidence is unchanged.
- ✅ Append-only discipline is preserved — recovery adds a checkpoint row, it
  never rewrites `audit_entries`.
- ⚠️ Entries beneath a baseline are trusted for *content* (hash) but not for
  *HMAC authenticity*; the trust root for the prefix is the operator's
  key-authenticated pin, recorded with a reason and timestamp.
- ⚠️ `AuditOp` grows to 33 variants; the closed-enum count test and the
  `#AuditOp` CUE enum are updated in the same change.

## Implementation Notes

- Domain: `crates/merkle-domain-audit-compliance/src/audit_baseline.rs`
  (`AuditBaseline` + `compute_mac` / `with_mac` / `verify_mac`); new
  `ChainOutcome::{BaselineMacMismatch, BaselineEntryMissing}`; new
  `ChainVerifyResult` fields `baseline_seq: Option<u64>` and
  `quarantined_below: u64`; `ChainVerifier::verify_from_baseline`.
- Ports: `Storage::audit_baseline()` / `set_audit_baseline()`.
- Adapter: migration `005_audit_baseline.sql` (single-row table, mirrors
  `pinned_head`); read/write impl in `audit.rs`.
- Application: `SetAuditBaselineCommand` (requires unsealed + operator
  confirmation); `VerifyChainQuery` and `doctor` use the baseline when present.
- Transport: `POST /audit/rebaseline`; OpenAPI updated. No MCP tool.
- CLI: `merkle audit rebaseline` with TTY confirmation.
- Types: `AuditOp::Rebaseline`; `exactly_32_variants` → `exactly_33_variants`.

## Related

- ADR-0009 — audit hash chain + pinned-head truncation witness.
- ADR-0015 — rust-keyring crate + macOS persistence-verification fallback.
- ADR-0021 — vault init ceremony (VRK derivation).
- BUG-05 / BUG-08 — VRK ↔ audit-HMAC key must feed identical bytes.

## Amendment 1 (2026-07-02): Root cause of the provenance incident — missing `apple-native` keyring feature

### Root cause

The incident described in the Context section was misdiagnosed at the time as
"macOS headless daemon can't persist to the OS keychain," matching the known
ADR-0015 Amendment 4 failure mode (background process lacks GUI auth, Security
framework silently no-ops the write). The actual root cause was different and
more basic: the workspace `Cargo.toml` pinned `keyring = "3.6"` with only the
`sync-secret-service` feature enabled (the Linux Secret Service backend). No
`apple-native` feature was enabled, so on macOS the `keyring` crate had no
platform backend compiled in at all and silently fell back to its **per-`Entry`
in-memory mock store**.

That mock store makes `store()` appear to succeed and even round-trips
correctly *within the same `Entry` instance* — which is exactly the
verify-after-write check that ADR-0015 Amendment 4 added. But the daemon's
`auto` backend probe constructs a **fresh** `Entry` for its write+verify+delete
sentinel round-trip (`dev.fapp.merkle/__merkle_probe_persist_check`) and a
**separate** `Entry` for the real VRK read on the next unseal. A fresh mock
`Entry` never sees another mock `Entry`'s writes, so the *probe* passed but the
real VRK retrieve returned `NotFound` on the next process invocation (or even
later in the same run, depending on `Entry` lifetime) — reproducing the exact
symptom the Amendment 4 persistence check exists to catch, without the cause
Amendment 4 was written against. The daemon correctly treated this as a
persistence failure and fell back to the `file` keystore backend mid-session,
which is what produced the VRK swap and the poisoned audit-HMAC window this
ADR's baseline mechanism recovers from.

### Fix

Enable the platform-native `keyring` features for every target OS in the
workspace `Cargo.toml`: `apple-native` (macOS Security framework, via
`Security.framework` FFI inside the crate — no new `unsafe` in Merkle code),
`windows-native` (Windows Credential Manager), alongside the existing
`sync-secret-service` (Linux). With `apple-native` enabled, `os_smoke`
(`crates/merkle-adapter-keychain/tests/os_smoke.rs`, `--ignored`) passes in
both a signed and an unsigned build inside a GUI login session, and the `auto`
probe's write+verify+delete round-trip exercises the real Keychain, not a mock.

### One-time file→keychain migration on upgrade

Vaults that were provisioned or ran for any period under the mock-store defect
persisted their VRK wrap (`vrk-master-v1`) to the `file` keystore, not the OS
keychain, even where `backend = "auto"` was configured and the operator
believed the OS keychain was in use. To avoid requiring a manual `merkle
rotate` / re-init after deploying the `apple-native` fix, the daemon now runs a
one-time, copy-only migration on startup:

- New `merkle_adapter_keychain::migrate_accounts(src, dst, service)`
  (`crates/merkle-adapter-keychain/src/migrate.rs`) copies keychain accounts
  from a source backend to a destination backend under a given service
  identifier. It **never overwrites** an account already present at the
  destination, and it **never deletes** the source entry — the file keystore
  is left intact as a cold backup after a successful migration.
- `maybe_migrate_file_keystore` (`bin/merkle-agent/src/run.rs`) invokes the
  migration at startup only when **all** of the following hold: the
  configured backend is `os`, or `auto` **and** the OS-keychain persistence
  probe just succeeded; the OS keychain does not already contain
  `vrk-master-v1`; a file keystore exists on disk; and
  `MERKLE_KEYSTORE_PASSPHRASE` is set in the environment (so the migration
  never blocks startup on an interactive TTY passphrase prompt).
- Migration failures are logged and do **not** abort startup — the daemon
  proceeds with whatever backend it already resolved. The migration is
  advisory acceleration, not a correctness dependency.
- The migrated VRK bytes are byte-identical to the source (a copy, not a
  re-wrap), so `derive_audit_hmac_key(vrk_bytes)` (ADR-0009 / BUG-05) produces
  the same audit-HMAC key before and after migration. The ADR-0029 trusted
  baseline pinned against the pre-migration incident is unaffected by running
  this migration afterward.

### Operational guidance

- After a successful migration (confirmed via `merkle status` / `vault.doctor`
  reporting the OS keychain as the active backend), operators should pin
  `[keystore] backend = "os"` explicitly in `~/.config/merkle/config.toml`
  rather than leaving `auto` — this removes any residual ambiguity from the
  startup probe and guarantees the daemon never silently falls back to `file`
  again for this vault.
- The on-disk `keystore.age` file and the launchd login-keychain passphrase
  entry (`dev.fapp.merkle.launchd`) become **cold-backup artifacts** once
  `backend = "os"` is pinned and migration is confirmed — they are not deleted
  automatically (per the copy-only, non-destructive migration contract above)
  and remain useful as a recovery path if the OS keychain becomes unavailable,
  but they are no longer read on the hot path.
- Operators upgrading from a pre-fix build should run `vault.doctor` after
  deploying the `apple-native`-enabled binary to confirm the migration ran and
  the OS keychain now holds `vrk-master-v1` before pinning `backend = "os"`.

### Related

- ADR-0015 — Amendment 4 (persistence-verification-on-write); this amendment
  clarifies that the verify-after-write check is not itself defective — it
  correctly detected a real persistence failure, just one with a different
  root cause (missing crate feature) than the amendment's own motivating
  scenario (headless GUI-auth denial).
