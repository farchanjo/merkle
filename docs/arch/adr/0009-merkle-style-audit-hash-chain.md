---
status: accepted
date: 2026-05-22
deciders: [farchanjo]
consulted: []
informed: []
---

# 0009. Merkle-Style Audit Hash Chain

## Context and Problem Statement

Every operation on a Secret (unseal, put, get, use, reveal, rotate,
delete, restore) must be recorded in an append-only audit log that
can be verified for tamper-evidence. If an attacker gains write
access to the database and modifies or removes an audit entry, the
modification must be detectable by the Chain Verifier without access
to any external timestamp authority or centralized service.

A flat append-only log does not provide tamper-evidence: an attacker
who can write to the database can add new entries after modifying
old ones, and the log looks plausible unless the reader holds a
prior snapshot. A hash chain, where each entry commits to its
predecessor, extends the tamper-evidence guarantee: any modification
to any historical entry invalidates all subsequent entries.

The project is named Merkle in honor of Ralph Merkle, whose work on
hash trees (Merkle trees) and cryptographic puzzles underlies this
audit design.

## Decision Drivers

* Tamper-evidence without external authority: the chain must be
  self-verifying using only the local database.
* Append-only enforcement: entries can only be added; the storage
  layer must enforce this via SQLite triggers.
* Fast hash function: computing and verifying the chain must be cheap
  even for large logs (millions of entries).
* Non-repudiation: once an entry is committed, it cannot be removed
  or modified without breaking the chain from that point forward.
* HMAC Signatures: the chain provides integrity; a detached HMAC
  (keyed on the vault HMAC key) provides authentication for remote
  sync.

## Considered Options

* Option A: BLAKE3 hash chain (each entry includes its own hash and
  the previous entry's hash)
* Option B: SHA-256 hash chain
* Option C: Flat append-only log with timestamps only
* Option D: External blockchain / distributed ledger

## Decision Outcome

Chosen option: "Option A: BLAKE3 hash chain", because BLAKE3 is
significantly faster than SHA-256 (often 3-5x on modern hardware),
is available as a pure-Rust crate without C FFI in the hot path
for this use case, and its XOF (extendable output function) mode
allows deriving per-vault HMAC keys without a separate KDF.

Each Audit Entry stores exactly two chain fields:
* `prev_hash`: the `current_hash` of the immediately preceding entry.
  The genesis entry uses the 64-hex-zero BLAKE3 sentinel
  `blake3:0000...0000` for `prev_hash`.
* `current_hash`: `BLAKE3(serialize(entry_without_hashes) || prev_hash)`.
  This single field ties the entry's content and its chain linkage
  together, which is simpler and equivalent to a 3-field
  (a deprecated 3-field form) for tamper detection.

The Chain Verifier iterates entries in `id` order, re-computes
`current_hash = BLAKE3(serialize(entry_without_hashes) || prev_hash)`
at each step, and asserts equality with the stored value. Any mismatch
indicates tampering from that entry forward.

```mermaid
flowchart LR
    G[Genesis Entry<br/>prev_hash=blake3:0000...0000]
    E1[Entry 1<br/>current_hash = BLAKE3(content || prev_hash)]
    E2[Entry 2<br/>current_hash = BLAKE3(content || E1.current_hash)]
    E3[Entry 3<br/>current_hash = BLAKE3(content || E2.current_hash)]
    G --> E1 --> E2 --> E3
```

### Consequences

* Good, because any single entry modification breaks the chain from
  that point forward; an attacker cannot silently alter history.
* Good, because removing an entry breaks the `prev_hash` link of the
  next entry; reordering is also detected.
* Good, because BLAKE3 computation is fast enough to verify millions
  of entries in seconds; the `doctor` command can run a full chain
  verification as part of its health report.
* Good, because the genesis entry's zero `prev_hash` is a
  well-known sentinel; the Chain Verifier does not need out-of-band
  knowledge to start verification.
* Bad, because the hash chain provides integrity, not
  authentication; an attacker with write access can truncate the log
  and rebuild a valid chain from the truncation point. The detached
  HMAC signature on each entry addresses authentication but requires
  the HMAC key to verify.
* Bad, because the chain is per-vault and local; it does not
  provide distributed non-repudiation. This is a known limitation
  for the local-first design.

## Pros and Cons of the Options

### Option A: BLAKE3 hash chain

* Good: fast; pure Rust; no C FFI.
* Good: XOF mode enables per-vault key derivation.
* Good: tamper-evidence for modification, removal, and reordering.
* Bad: local only; truncation attack requires HMAC to counter.

### Option B: SHA-256 hash chain

* Good: FIPS-approved; widely understood.
* Bad: 3-5x slower than BLAKE3 for chain verification on large logs.
* Bad: no XOF mode; requires a separate HKDF step for key derivation.

### Option C: Flat append-only log with timestamps only

* Good: simplest implementation; no hash computation.
* Bad: no tamper-evidence; modifying an entry is undetectable by
  reading the log alone.
* Bad: timestamps are not trustworthy (system clock manipulation).

### Option D: External blockchain / distributed ledger

* Good: distributed non-repudiation; timestamps anchored externally.
* Bad: requires network access; violates the local-first design.
* Bad: enormously complex for a single-user vault; operational
  overhead is disproportionate.

## Validation

* Integrity test: insert 1,000 audit entries; verify chain; assert
  zero errors.
* Tamper detection: insert 1,000 entries; modify entry 500's
  content; re-run verifier; assert `current_hash` mismatch at entry 500.
* Removal detection: insert 1,000 entries; delete entry 300; re-run
  verifier; assert failure at entry 301 (missing prev_hash).
* Reorder detection: insert 1,000 entries; swap entries 200 and 201;
  assert failure at entry 200.
* Truncation detection (HMAC path): verify that truncating the log
  at entry 500 and re-building a valid chain fails HMAC signature
  verification for the anchor entry.

## More Information

* BLAKE3 specification: `https://github.com/BLAKE3-team/BLAKE3-specs`.
* `blake3` crate: `https://crates.io/crates/blake3`.
* Ralph Merkle — "A Digital Signature Based on a Conventional
  Encryption Function" (1987).
* Related: [0003-sqlite-with-per-blob-encryption.md](0003-sqlite-with-per-blob-encryption.md)
* Related: [0014-retention-policy-default-retain-count-three.md](0014-retention-policy-default-retain-count-three.md)

## Amendment — 2026-05-22

### Chain-Head Pinning (mandatory)

After every successful audit entry append, the agent MUST write the resulting
`current_hash` value synchronously to a separate file `audit_head.json` in the
same directory as `audit.jsonl`. The file contains a single JSON object:

```json
{
  "seq": <u64>,
  "current_hash": "<hex-encoded BLAKE3 hash>",
  "written_at": "<RFC 3339 timestamp>"
}
```

The write MUST use `O_SYNC` semantics (or `File::flush` + `File::sync_all`) to
ensure the file is on persistent storage before the corresponding vault operation
completes. `audit_head.json` is created with mode `0600`.

The Chain Verifier (`merkle doctor --verify-audit`) MUST compare the hash it
computes by full chain reconstruction against the value in `audit_head.json`. If
they differ, the verifier MUST report `CHAIN_HEAD_MISMATCH` regardless of whether
the internal chain links are self-consistent. This detects an attacker who truncates
the log, rebuilds a valid sub-chain, and updates the internal entries, but cannot
forge the pinned head without the HMAC key.

### HMAC Synchronous Write (mandatory)

The per-entry HMAC signature MUST be computed synchronously at entry write time,
before `fsync`. Lazy computation (e.g., batching HMAC computation for a subsequent
remote-sync flush) is not permitted. Rationale: if the agent crashes after writing
the entry but before computing the HMAC, the entry will have no HMAC tag and will
fail remote sync verification. Computing HMAC synchronously ensures that any entry
on disk is either fully signed or absent.

The HMAC is keyed with the Vault HMAC Key (see
[0006-age-encryption-for-backups-and-recovery.md](0006-age-encryption-for-backups-and-recovery.md)
Amendment — 2026-05-22 for the key derivation).

### Truncation Attack (residual risk, documented)

A local attacker with write access to `audit.jsonl` can truncate the file at an
arbitrary byte offset. If the truncation happens at an entry boundary, the attacker
can then append new (attacker-crafted) entries to produce a self-consistent sub-
chain from the truncation point forward.

**Mitigations:**

- Chain-head pinning (above) makes this attack detectable: the reconstructed chain
  head from the truncated log will not match `audit_head.json` unless the attacker
  also forges `audit_head.json`, which requires the HMAC key.
- Monotonic sequence numbers in each entry mean a gap is detectable even if the
  chain from the truncation point appears internally valid.
- Remote sync (opt-in, ADR-0009 `Bad` consequence) provides an out-of-band
  witness that the full chain existed at the time of the last sync.

**Accepted residual risk:** without remote sync enabled, a sufficiently privileged
attacker who can forge or replace `audit_head.json` (which requires the HMAC key)
can erase evidence of the truncation. This is accepted as the local-first design's
known limitation and is documented in the operations runbook as a requirement to
enable remote sync for high-security deployments.

Cross-reference: [0006-age-encryption-for-backups-and-recovery.md](0006-age-encryption-for-backups-and-recovery.md),
[0018-full-coverage-validation-as-architectural-contract.md](0018-full-coverage-validation-as-architectural-contract.md) — the TLA+
hash-chain integrity spec and the AsyncAPI audit-event schema machine-verify
the invariants recorded in this ADR.

## Implementation Note — 2026-05-24

`GET /v1/audit?verify_chain=true` MUST invoke `ChainVerifier::verify()` over
the returned entries and populate the response `chain_valid` field with the
boolean result before sending the response. Returning `null` (i.e., leaving
the field unset) is a contract violation: the OpenAPI schema declares
`chain_valid` as `type: boolean`, and downstream callers — including the MCP
`vault.audit.query` tool — pattern-match on `true`/`false` to surface audit
integrity status to the operator.

The root-cause location is `crates/merkle-application/src/queries/query_audit.rs`,
where the `verify_chain` flag was parsed but `ChainVerifier::verify()` was not
called. The fix wires the verifier call and maps the outcome to the response DTO.

Cross-reference: [ADR-0025](0025-post-phase-2-cosmetic-cleanup.md) §Bug #3
documents this gap, its root cause, fix location, and the required TDD test.
