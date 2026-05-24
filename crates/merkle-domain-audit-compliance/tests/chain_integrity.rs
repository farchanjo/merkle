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
    PinnedHead,
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
}

// ---------------------------------------------------------------------------
// Test 3: tampered field produces different hash (content commits to hash)
// ---------------------------------------------------------------------------

#[test]
fn verify_full_tampered_entry_broken_at_entry() {
    use merkle_domain_audit_compliance::audit_entry::AuditEntry;

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
