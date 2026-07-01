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
