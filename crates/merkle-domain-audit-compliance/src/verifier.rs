//! `ChainVerifier` — DomainService for validating the BLAKE3 audit hash chain.
//!
//! The verifier is **read-only**; it never writes to the log. It walks entries
//! in ascending sequence order, recomputes each `current_hash`, and checks the
//! HMAC tag when a key is supplied. It also compares the final reconstructed
//! head against the [`PinnedHead`] to detect truncation attacks (ADR-0009
//! Amendment).
//!
//! # Truncation detection
//!
//! If an attacker truncates the log and rebuilds a valid sub-chain, the
//! reconstructed head's `seq` will be less than `pinned_head.head_seq`.
//! The verifier reports this as [`ChainOutcome::TruncationDetected`].

use merkle_types::{AuditEntryId, Blake3Hash, HmacSignature, Rfc3339Timestamp, hash::GENESIS};

use crate::{
    audit_entry::AuditEntry,
    audit_log::AuditLog,
    chain_verify_result::{ChainOutcome, ChainVerifyResult},
    pinned_head::PinnedHead,
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// State accumulated while walking the entry slice.
struct WalkState {
    last_hash: Blake3Hash,
    last_seq: Option<u64>,
    entries_checked: u64,
    anomalies_detected: u32,
    first_entry: bool,
}

impl WalkState {
    fn new() -> Self {
        Self {
            last_hash: GENESIS,
            last_seq: None,
            entries_checked: 0,
            anomalies_detected: 0,
            first_entry: true,
        }
    }
}

/// Build a broken-at-entry result from the current walk state.
fn broken_at(
    entry: &AuditEntry,
    expected_prev: Blake3Hash,
    state: &WalkState,
    from_id: Option<AuditEntryId>,
    to_id: Option<AuditEntryId>,
    verified_at: Rfc3339Timestamp,
) -> ChainVerifyResult {
    let actual_prev = entry.prev_hash;
    ChainVerifyResult {
        outcome: ChainOutcome::BrokenAtEntry {
            broken_at_id: entry.id,
            expected_prev,
            actual_prev,
        },
        head_hash: None,
        entries_checked: state.entries_checked,
        anomalies_detected: state.anomalies_detected + 1,
        range_from_id: from_id,
        range_to_id: to_id,
        triggered_by: None,
        verified_at,
    }
}

/// Check the sequence-number gap and `prev_hash` pointer for a non-first entry.
///
/// Returns `Err(Box<ChainVerifyResult>)` when a violation is detected so the
/// caller can short-circuit with an early `return`.
fn check_link(
    entry: &AuditEntry,
    state: &WalkState,
    from_id: Option<AuditEntryId>,
    to_id: Option<AuditEntryId>,
    verified_at: Rfc3339Timestamp,
) -> Result<(), Box<ChainVerifyResult>> {
    if let Some(prev_seq) = state.last_seq {
        if entry.seq != prev_seq + 1 {
            return Err(Box::new(broken_at(
                entry,
                state.last_hash,
                state,
                from_id,
                to_id,
                verified_at,
            )));
        }
    }
    if entry.prev_hash != Some(state.last_hash) {
        return Err(Box::new(broken_at(
            entry,
            state.last_hash,
            state,
            from_id,
            to_id,
            verified_at,
        )));
    }
    Ok(())
}

/// Verify the recomputed `current_hash` against the stored value.
///
/// Returns `Err(Box<ChainVerifyResult>)` on mismatch.
fn check_hash(
    entry: &AuditEntry,
    prev_for_hashing: &Blake3Hash,
    state: &WalkState,
    from_id: Option<AuditEntryId>,
    to_id: Option<AuditEntryId>,
    verified_at: Rfc3339Timestamp,
) -> Result<(), Box<ChainVerifyResult>> {
    let Ok(canonical) = entry.canonical_bytes_for_hashing(prev_for_hashing) else {
        // Serialization failure — treat as anomaly and continue walking.
        return Ok(());
    };
    let recomputed = Blake3Hash::hash(&canonical);
    if recomputed != entry.current_hash {
        return Err(Box::new(broken_at(
            entry,
            *prev_for_hashing,
            state,
            from_id,
            to_id,
            verified_at,
        )));
    }
    Ok(())
}

/// Verify the HMAC tag on one entry when a valid key is available.
///
/// Returns `Err(Box<ChainVerifyResult>)` on mismatch.
fn check_hmac(
    entry: &AuditEntry,
    hmac_key: Option<&[u8; 32]>,
    state: &WalkState,
    from_id: Option<AuditEntryId>,
    to_id: Option<AuditEntryId>,
    verified_at: Rfc3339Timestamp,
) -> Result<(), Box<ChainVerifyResult>> {
    let (Some(key), Some(stored_hmac)) = (hmac_key, entry.hmac) else {
        return Ok(());
    };
    let mut hmac_input = Vec::with_capacity(48);
    hmac_input.extend_from_slice(entry.current_hash.as_bytes());
    let id_uuid = entry.id.inner();
    hmac_input.extend_from_slice(id_uuid.as_bytes());
    let expected = HmacSignature::compute(key, &hmac_input);
    if expected != stored_hmac {
        return Err(Box::new(ChainVerifyResult {
            outcome: ChainOutcome::HmacMismatch { entry_id: entry.id },
            head_hash: None,
            entries_checked: state.entries_checked,
            anomalies_detected: state.anomalies_detected + 1,
            range_from_id: from_id,
            range_to_id: to_id,
            triggered_by: None,
            verified_at,
        }));
    }
    Ok(())
}

/// Collect the slice of entries that fall within `[from_id, to_id]`.
fn slice_entries<'a>(
    log: &'a AuditLog,
    from_id: Option<&AuditEntryId>,
    to_id: Option<&AuditEntryId>,
) -> Vec<&'a AuditEntry> {
    let mut iter = log.iter().peekable();

    if let Some(start_id) = from_id {
        while let Some(e) = iter.peek() {
            if &e.id == start_id {
                break;
            }
            iter.next();
        }
    }

    let mut collected = Vec::new();
    for e in iter {
        collected.push(e);
        if let Some(end_id) = to_id {
            if &e.id == end_id {
                break;
            }
        }
    }
    collected
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Stateless chain-integrity verifier.
///
/// Both [`ChainVerifier::verify_full`] and [`ChainVerifier::verify_range`]
/// return a [`ChainVerifyResult`] describing the outcome. They never panic and
/// never write to the log.
pub struct ChainVerifier;

impl ChainVerifier {
    /// Verify the full chain from the genesis entry to the last entry.
    ///
    /// Also compares the reconstructed head against `pinned_head` to detect
    /// truncation attacks (ADR-0009 Amendment).
    #[must_use]
    pub fn verify_full(
        log: &AuditLog,
        pinned_head: &PinnedHead,
        hmac_key: &[u8],
    ) -> ChainVerifyResult {
        Self::verify_range(log, pinned_head, None, None, hmac_key)
    }

    /// Verify a contiguous sub-range of the chain.
    ///
    /// - `from_id`: if `Some`, verification starts at the first entry whose id
    ///   equals `from_id`; entries before it are skipped.
    /// - `to_id`: if `Some`, verification stops at the entry whose id equals
    ///   `to_id` (inclusive).
    ///
    /// When both are `None` this is equivalent to a full verification pass.
    #[must_use]
    pub fn verify_range(
        log: &AuditLog,
        pinned_head: &PinnedHead,
        from_id: Option<AuditEntryId>,
        to_id: Option<AuditEntryId>,
        hmac_key: &[u8],
    ) -> ChainVerifyResult {
        let verified_at = Rfc3339Timestamp::now();
        let hmac_key_array: Option<&[u8; 32]> = hmac_key.try_into().ok();

        let entries = slice_entries(log, from_id.as_ref(), to_id.as_ref());

        if entries.is_empty() {
            return ChainVerifyResult {
                outcome: ChainOutcome::Intact,
                head_hash: log.head().copied(),
                entries_checked: 0,
                anomalies_detected: 0,
                range_from_id: from_id,
                range_to_id: to_id,
                triggered_by: None,
                verified_at,
            };
        }

        let mut state = WalkState::new();

        for entry in &entries {
            state.entries_checked += 1;

            let prev_for_hashing = if state.first_entry {
                entry.prev_hash.unwrap_or(GENESIS)
            } else {
                state.last_hash
            };

            if !state.first_entry {
                if let Err(r) = check_link(entry, &state, from_id, to_id, verified_at) {
                    return *r;
                }
            }

            if let Err(r) = check_hash(
                entry,
                &prev_for_hashing,
                &state,
                from_id,
                to_id,
                verified_at,
            ) {
                return *r;
            }

            if let Err(r) = check_hmac(entry, hmac_key_array, &state, from_id, to_id, verified_at) {
                return *r;
            }

            state.last_hash = entry.current_hash;
            state.last_seq = Some(entry.seq);
            state.first_entry = false;
        }

        let final_head_hash = state.last_hash;
        let final_seq = state.last_seq.unwrap_or(0);

        // Truncation detection: full-range only (both bounds are None).
        if from_id.is_none() && to_id.is_none() && pinned_head.head_seq > final_seq {
            return ChainVerifyResult {
                outcome: ChainOutcome::TruncationDetected {
                    last_pinned_seq: pinned_head.head_seq,
                    last_actual_seq: final_seq,
                },
                head_hash: Some(final_head_hash),
                entries_checked: state.entries_checked,
                anomalies_detected: state.anomalies_detected + 1,
                range_from_id: None,
                range_to_id: None,
                triggered_by: None,
                verified_at,
            };
        }

        ChainVerifyResult {
            outcome: ChainOutcome::Intact,
            head_hash: Some(final_head_hash),
            entries_checked: state.entries_checked,
            anomalies_detected: state.anomalies_detected,
            range_from_id: from_id,
            range_to_id: to_id,
            triggered_by: None,
            verified_at,
        }
    }
}
