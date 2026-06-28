//! Integration tests: audit hash chain integrity, tamper detection, and
//! truncation detection.
//!
//! Test plan:
//! 1. `append_produces_correct_chain_link` — hash equation holds end-to-end.
//! 2. `verify_full_intact_chain` — intact chain returns `Intact`.
//! 3. `verify_full_tampered_entry_broken_at_entry` — mutated field → different hash.
//! 4. `verify_full_truncated_chain` — missing tail entries → `TruncationDetected`.
//! 5. `verify_full_hmac_mismatch` — wrong key → `HmacMismatch`.
//! 6. `query_model_filters_by_outcome` — AuditQueryModel AND-filters work.
//! 7. `genesis_entry_has_no_prev_hash_and_seq_zero` — genesis invariants.
//! 8. `deny_entry_carries_denial_reason` — denial payload is preserved.
//! 9. `verify_link_detects_prev_hash_mismatch` — verify_link rejects reverse link.
//! 10. Proptest: N appended entries → `verify_full == Intact`.

use merkle_domain_audit_compliance::{
    AppendParams, AuditLog, AuditQuery, AuditQueryModel, AuditWriter, ChainOutcome, ChainVerifier,
    PinnedHead, audit_entry::AuditEntry,
};
use merkle_types::{
    AuditEntryId, AuditOp, AuditOutcome, Blake3Hash, NamespaceId, Rfc3339Timestamp, hash::GENESIS,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const HMAC_KEY: [u8; 32] = [0xAB; 32];

fn test_namespace() -> NamespaceId {
    NamespaceId::new()
}

fn put_allow(log: &mut AuditLog, ns: NamespaceId) -> PinnedHead {
    let (_, head) = AuditWriter::append(
        log,
        AppendParams::new(AuditOp::Put, AuditOutcome::Allow, ns),
        &HMAC_KEY,
    )
    .expect("append must succeed");
    head
}

/// Append `count` allow/put entries to `log` and return the final `PinnedHead`.
fn fill_log(log: &mut AuditLog, count: usize) -> PinnedHead {
    let ns = test_namespace();
    let mut last_head = PinnedHead::new(GENESIS, 0, AuditEntryId::new(), Rfc3339Timestamp::now());
    for _ in 0..count {
        last_head = put_allow(log, ns);
    }
    last_head
}

/// Append `count` allow/put entries and return them verbatim alongside the final
/// authenticated `PinnedHead`. Used to feed a hand-tampered chain to the
/// verifier via [`AuditLog::from_persisted`].
fn append_entries(count: usize) -> (Vec<AuditEntry>, PinnedHead) {
    let mut log = AuditLog::new();
    let ns = test_namespace();
    let mut entries = Vec::with_capacity(count);
    let mut head = PinnedHead::new(GENESIS, 0, AuditEntryId::new(), Rfc3339Timestamp::now());
    for _ in 0..count {
        let (entry, pinned) = AuditWriter::append(
            &mut log,
            AppendParams::new(AuditOp::Put, AuditOutcome::Allow, ns),
            &HMAC_KEY,
        )
        .expect("append must succeed");
        entries.push(entry);
        head = pinned;
    }
    (entries, head)
}

// ---------------------------------------------------------------------------
// Test 1: chain link equation
// ---------------------------------------------------------------------------

#[test]
fn append_produces_correct_chain_link() {
    let mut log = AuditLog::new();
    let ns = test_namespace();

    let (entry1, _) = AuditWriter::append(
        &mut log,
        AppendParams::new(AuditOp::Put, AuditOutcome::Allow, ns).caller_program("merkle-agent"),
        &HMAC_KEY,
    )
    .expect("first append");

    // Genesis: prev_hash field is None, hashing uses GENESIS sentinel.
    assert!(
        entry1.prev_hash.is_none(),
        "genesis entry must have no prev_hash"
    );
    assert_eq!(entry1.seq, 0);

    // Recompute current_hash manually.
    let canonical = entry1
        .canonical_bytes_for_hashing(&GENESIS)
        .expect("canonical bytes");
    let recomputed = Blake3Hash::hash(&canonical);
    assert_eq!(
        entry1.current_hash, recomputed,
        "current_hash must equal BLAKE3(canonical || GENESIS)"
    );

    let (entry2, _) = AuditWriter::append(
        &mut log,
        AppendParams::new(AuditOp::Get, AuditOutcome::Allow, ns),
        &HMAC_KEY,
    )
    .expect("second append");

    assert_eq!(entry2.seq, 1, "second entry seq must be 1");
    assert_eq!(
        entry2.prev_hash,
        Some(entry1.current_hash),
        "prev_hash of second entry must equal first entry current_hash"
    );

    let canonical2 = entry2
        .canonical_bytes_for_hashing(&entry1.current_hash)
        .expect("canonical bytes for entry2");
    let recomputed2 = Blake3Hash::hash(&canonical2);
    assert_eq!(entry2.current_hash, recomputed2);
}

// ---------------------------------------------------------------------------
// Test 2: intact chain
// ---------------------------------------------------------------------------

#[test]
fn verify_full_intact_chain() {
    let mut log = AuditLog::new();
    let pinned = fill_log(&mut log, 10);
    let result = ChainVerifier::verify_full(&log, &pinned, &HMAC_KEY);
    assert_eq!(
        result.outcome,
        ChainOutcome::Intact,
        "intact chain must verify as Intact"
    );
    assert_eq!(result.entries_checked, 10);
    assert_eq!(result.anomalies_detected, 0);
    assert!(
        result.hmac_checked,
        "a 32-byte key over a non-empty chain must report hmac_checked=true"
    );
}

// ---------------------------------------------------------------------------
// Test 4b: head-hash mismatch (tail-rewrite / pinned-head divergence)
// ---------------------------------------------------------------------------

#[test]
fn verify_full_head_hash_mismatch() {
    let mut log = AuditLog::new();
    let pinned = fill_log(&mut log, 5);

    // A pinned head with the correct seq but a wrong head_hash models a
    // rewritten chain tip whose entry count is preserved. The MAC is recomputed
    // over the forged fields (the attacker is given the key here) so the head
    // authentication passes and the reconstructed-tip equality check is the one
    // that must reject the divergence.
    let forged = PinnedHead::new(
        GENESIS,
        pinned.head_seq,
        pinned.head_id,
        Rfc3339Timestamp::now(),
    )
    .with_head_mac(&HMAC_KEY, pinned.head_seq + 1);
    let result = ChainVerifier::verify_full(&log, &forged, &HMAC_KEY);
    assert!(
        matches!(result.outcome, ChainOutcome::HeadHashMismatch { .. }),
        "head-hash divergence at the same seq must be rejected, got {:?}",
        result.outcome
    );
}

// ---------------------------------------------------------------------------
// Test 4c: malformed HMAC key is a failure, never a silent hash-only downgrade
// ---------------------------------------------------------------------------

#[test]
fn verify_full_rejects_malformed_hmac_key() {
    let mut log = AuditLog::new();
    let pinned = fill_log(&mut log, 3);

    let short_key = [0xABu8; 16]; // not 32 bytes
    let result = ChainVerifier::verify_full(&log, &pinned, &short_key);
    assert_eq!(
        result.outcome,
        ChainOutcome::HmacKeyUnavailable,
        "a non-32-byte key must fail, not silently skip HMAC"
    );
    assert!(!result.hmac_checked);
}

// ---------------------------------------------------------------------------
// Test 4d: empty key is an explicit hash-only pass (hmac_checked == false)
// ---------------------------------------------------------------------------

#[test]
fn verify_full_empty_key_is_hash_only() {
    let mut log = AuditLog::new();
    let pinned = fill_log(&mut log, 3);

    let result = ChainVerifier::verify_full(&log, &pinned, &[]);
    assert_eq!(
        result.outcome,
        ChainOutcome::Intact,
        "an intact hash chain with no key must still pass the hash-only check"
    );
    assert!(
        !result.hmac_checked,
        "no key supplied means the HMAC was not verified"
    );
}

// ---------------------------------------------------------------------------
// Test 3: tampered field produces different hash (content commits to hash)
// ---------------------------------------------------------------------------

#[test]
fn verify_full_tampered_entry_broken_at_entry() {
    let mut log = AuditLog::new();
    let ns = test_namespace();

    let (entry1, _) = AuditWriter::append(
        &mut log,
        AppendParams::new(AuditOp::Put, AuditOutcome::Allow, ns),
        &HMAC_KEY,
    )
    .expect("e1");

    let original_hash = entry1.current_hash;

    // Construct a fake entry with the same fields but a different op.
    let tampered = AuditEntry {
        op: AuditOp::Delete,
        ..entry1.clone()
    };
    let tampered_canonical = tampered
        .canonical_bytes_for_hashing(&GENESIS)
        .expect("canonical");
    let tampered_hash = Blake3Hash::hash(&tampered_canonical);

    assert_ne!(
        tampered_hash, original_hash,
        "tampered content must produce a different hash"
    );
}

// ---------------------------------------------------------------------------
// Test 4: truncation detection
// ---------------------------------------------------------------------------

#[test]
fn verify_full_truncated_chain() {
    // Build two independent logs: one with 5 entries (produces pinned_seq=4)
    // and one with only 3 entries (produces pinned_seq=2).
    let mut full_log = AuditLog::new();
    let full_pinned = fill_log(&mut full_log, 5);
    assert_eq!(full_pinned.head_seq, 4);

    let mut truncated_log = AuditLog::new();
    let truncated_pinned = fill_log(&mut truncated_log, 3);
    assert_eq!(truncated_pinned.head_seq, 2);

    // Verify the 3-entry log against the 5-entry pinned head.
    let result = ChainVerifier::verify_full(&truncated_log, &full_pinned, &HMAC_KEY);
    assert_eq!(
        result.outcome,
        ChainOutcome::TruncationDetected {
            last_pinned_seq: 4,
            last_actual_seq: 2
        },
        "truncation must be detected when log is shorter than pinned head"
    );

    // The 3-entry log is internally consistent.
    let intact = ChainVerifier::verify_full(&truncated_log, &truncated_pinned, &HMAC_KEY);
    assert_eq!(intact.outcome, ChainOutcome::Intact);
}

// ---------------------------------------------------------------------------
// Test 5: HMAC mismatch detection
// ---------------------------------------------------------------------------

#[test]
fn verify_full_hmac_mismatch() {
    let mut log = AuditLog::new();
    let pinned = fill_log(&mut log, 3);

    let wrong_key = [0x00u8; 32];
    let result = ChainVerifier::verify_full(&log, &pinned, &wrong_key);

    assert!(
        matches!(result.outcome, ChainOutcome::HmacMismatch { .. }),
        "wrong key must cause HmacMismatch, got {:?}",
        result.outcome
    );
}

// ---------------------------------------------------------------------------
// Test 6: AuditQueryModel filtering
// ---------------------------------------------------------------------------

#[test]
fn query_model_filters_by_outcome() {
    let mut log = AuditLog::new();
    let ns = test_namespace();

    AuditWriter::append(
        &mut log,
        AppendParams::new(AuditOp::Put, AuditOutcome::Allow, ns),
        &HMAC_KEY,
    )
    .expect("allow entry");

    AuditWriter::append(
        &mut log,
        AppendParams::new(AuditOp::Get, AuditOutcome::Deny, ns).denial_reason("rejected_policy"),
        &HMAC_KEY,
    )
    .expect("deny entry");

    let model = AuditQueryModel::new(&log);

    let deny_results = model.execute(&AuditQuery {
        outcome: Some(AuditOutcome::Deny),
        ..AuditQuery::default()
    });
    assert_eq!(deny_results.len(), 1);
    assert_eq!(deny_results[0].outcome, AuditOutcome::Deny);

    let allow_results = model.execute(&AuditQuery {
        outcome: Some(AuditOutcome::Allow),
        ..AuditQuery::default()
    });
    assert_eq!(allow_results.len(), 1);

    let all_results = model.execute(&AuditQuery::default());
    assert_eq!(all_results.len(), 2);
}

// ---------------------------------------------------------------------------
// Test 7: genesis invariants
// ---------------------------------------------------------------------------

#[test]
fn genesis_entry_has_no_prev_hash_and_seq_zero() {
    let mut log = AuditLog::new();
    let ns = test_namespace();
    let (entry, _) = AuditWriter::append(
        &mut log,
        AppendParams::new(AuditOp::Unseal, AuditOutcome::Allow, ns),
        &HMAC_KEY,
    )
    .expect("genesis");
    assert!(entry.prev_hash.is_none());
    assert_eq!(entry.seq, 0);
    assert!(
        entry.hmac.is_some(),
        "HMAC must always be set synchronously"
    );
}

// ---------------------------------------------------------------------------
// Test 8: denial reason payload
// ---------------------------------------------------------------------------

#[test]
fn deny_entry_carries_denial_reason() {
    let mut log = AuditLog::new();
    let ns = test_namespace();
    let (entry, _) = AuditWriter::append(
        &mut log,
        AppendParams::new(AuditOp::Reveal, AuditOutcome::Deny, ns)
            .denial_reason("rejected_oob_timeout"),
        &HMAC_KEY,
    )
    .expect("deny entry");
    assert_eq!(entry.outcome, AuditOutcome::Deny);
    assert!(entry.denial_reason.is_some());
}

// ---------------------------------------------------------------------------
// Test 9: verify_link rejects reverse / wrong-predecessor link
// ---------------------------------------------------------------------------

#[test]
fn verify_link_detects_prev_hash_mismatch() {
    let mut log = AuditLog::new();
    let ns = test_namespace();

    let (entry1, _) = AuditWriter::append(
        &mut log,
        AppendParams::new(AuditOp::Put, AuditOutcome::Allow, ns),
        &HMAC_KEY,
    )
    .expect("entry1");

    let (entry2, _) = AuditWriter::append(
        &mut log,
        AppendParams::new(AuditOp::Get, AuditOutcome::Allow, ns),
        &HMAC_KEY,
    )
    .expect("entry2");

    // Forward link must be valid.
    entry2.verify_link(&entry1).expect("valid link");

    // Reverse: entry1 is not the successor of entry2.
    let err = entry1.verify_link(&entry2);
    assert!(err.is_err(), "reverse link must be rejected");
}

// ---------------------------------------------------------------------------
// MERK-002: a keyed pass must reject an entry that carries no HMAC tag
// ---------------------------------------------------------------------------

#[test]
fn verify_full_missing_hmac_tag_is_not_intact() {
    let (mut entries, pinned) = append_entries(3);

    // Strip the HMAC tag from a middle entry. The BLAKE3 hash chain still lines
    // up (the tag is excluded from canonical bytes), so before the fix this
    // would slip through as Intact — the only keyed integrity check skipped.
    let victim_id = entries[1].id;
    entries[1] = AuditEntry {
        hmac: None,
        ..entries[1].clone()
    };

    let log = AuditLog::from_persisted(entries);
    let result = ChainVerifier::verify_full(&log, &pinned, &HMAC_KEY);

    assert_eq!(
        result.outcome,
        ChainOutcome::MissingHmac {
            entry_id: victim_id
        },
        "a present key over an entry with no HMAC must fail, not silently skip"
    );
    assert!(!result.is_intact());
}

// ---------------------------------------------------------------------------
// MERK-003(a): a full pass that does not begin at the genesis anchor must fail
// ---------------------------------------------------------------------------

#[test]
fn verify_full_deleted_genesis_prefix_is_not_intact() {
    let (entries, pinned) = append_entries(4);

    // Remove the genesis entry (seq 0). The remaining chain is internally
    // self-consistent from seq 1 onward, so the per-link and head checks would
    // pass; only the genesis anchor catches the removed prefix.
    let beheaded: Vec<AuditEntry> = entries.into_iter().skip(1).collect();
    let first_id = beheaded[0].id;
    let first_seq = beheaded[0].seq;

    let log = AuditLog::from_persisted(beheaded);
    let result = ChainVerifier::verify_full(&log, &pinned, &HMAC_KEY);

    assert_eq!(
        result.outcome,
        ChainOutcome::GenesisAnchorMissing {
            entry_id: first_id,
            found_seq: first_seq,
        },
        "a full pass whose first entry is not the genesis anchor must fail"
    );
    assert!(!result.is_intact());
}

// ---------------------------------------------------------------------------
// MERK-003(b): a rewritten pinned head cannot be re-authenticated without the
// key, even when its head fields are made consistent with a truncated log
// ---------------------------------------------------------------------------

#[test]
fn verify_full_rewritten_pinned_head_mac_mismatch() {
    let mut log = AuditLog::new();
    let pinned = fill_log(&mut log, 3);

    // Baseline: the genuine, authenticated pinned head verifies clean.
    assert_eq!(
        ChainVerifier::verify_full(&log, &pinned, &HMAC_KEY).outcome,
        ChainOutcome::Intact,
        "the genuine authenticated head must verify Intact"
    );

    // Attacker rewrites the pinned head's tag. Head fields stay consistent with
    // the log (so truncation/tip checks alone would pass) but the MAC, forged
    // under the wrong key, cannot be re-authenticated.
    let wrong_key = [0x00u8; 32];
    let forged_mac = pinned.compute_head_mac(&wrong_key, pinned.head_seq + 1);
    let forged = PinnedHead {
        hmac_head: Some(forged_mac),
        ..pinned.clone()
    };

    let result = ChainVerifier::verify_full(&log, &forged, &HMAC_KEY);
    assert_eq!(
        result.outcome,
        ChainOutcome::HeadMacMismatch {
            head_id: pinned.head_id,
        },
        "an unauthenticated pinned head must be rejected before its fields are trusted"
    );
    assert!(!result.is_intact());
}

// ---------------------------------------------------------------------------
// MERK-003(c): deleting EVERY audit entry while keeping a genuine pinned head
// (full-log truncation) must NOT verify as Intact — the empty-log branch
// previously early-returned Intact without consulting the pinned head.
// ---------------------------------------------------------------------------

#[test]
fn verify_full_full_log_truncation_keeps_head_is_not_intact() {
    // Build a real 3-entry chain and capture its authenticated pinned head.
    let mut full = AuditLog::new();
    let pinned = fill_log(&mut full, 3);
    assert_eq!(
        ChainVerifier::verify_full(&full, &pinned, &HMAC_KEY).outcome,
        ChainOutcome::Intact,
        "sanity: the intact chain verifies clean"
    );

    // Attacker deletes every `audit_entries` row but leaves the `pinned_head`
    // singleton (still carrying its genuine head MAC). On a full-range pass the
    // verifier must detect the full truncation rather than reporting Intact.
    let empty = AuditLog::new();
    let result = ChainVerifier::verify_full(&empty, &pinned, &HMAC_KEY);

    assert_eq!(
        result.outcome,
        ChainOutcome::TruncationDetected {
            last_pinned_seq: pinned.head_seq,
            last_actual_seq: 0,
        },
        "deleting all entries while keeping the pinned head must be flagged as truncation, not Intact"
    );
    assert!(!result.is_intact());
}

// ---------------------------------------------------------------------------
// Proptest: N appended entries → verify_full == Intact
// ---------------------------------------------------------------------------

use proptest::prelude::*;

proptest! {
    #[test]
    fn proptest_n_entries_verify_intact(count in 1usize..=50usize) {
        let mut log = AuditLog::new();
        let pinned = fill_log(&mut log, count);
        let result = ChainVerifier::verify_full(&log, &pinned, &HMAC_KEY);
        prop_assert_eq!(result.outcome, ChainOutcome::Intact);
        prop_assert_eq!(result.entries_checked, count as u64);
        prop_assert_eq!(result.anomalies_detected, 0);
    }
}
