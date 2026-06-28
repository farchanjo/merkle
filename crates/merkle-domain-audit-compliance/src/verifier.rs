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
        hmac_checked: false,
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
        // Serialization failure on the audit path is itself an integrity
        // anomaly: the entry can no longer be proven to commit to its stored
        // hash, so it MUST fail verification rather than be silently skipped.
        return Err(Box::new(ChainVerifyResult {
            outcome: ChainOutcome::EntrySerializationFailed { entry_id: entry.id },
            head_hash: None,
            entries_checked: state.entries_checked,
            anomalies_detected: state.anomalies_detected + 1,
            hmac_checked: false,
            range_from_id: from_id,
            range_to_id: to_id,
            triggered_by: None,
            verified_at,
        }));
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
    // No key supplied → explicit hash-only pass; the tag is not examined.
    let Some(key) = hmac_key else {
        return Ok(());
    };
    // A key IS present, so every entry MUST carry a tag to authenticate. A
    // missing tag can no longer be silently accepted: that would skip the only
    // keyed integrity check (MERK-002). Persisting a NULL tag is also blocked at
    // the storage layer (`hmac NOT NULL`).
    let Some(stored_hmac) = entry.hmac else {
        return Err(Box::new(ChainVerifyResult {
            outcome: ChainOutcome::MissingHmac { entry_id: entry.id },
            head_hash: None,
            entries_checked: state.entries_checked,
            anomalies_detected: state.anomalies_detected + 1,
            hmac_checked: false,
            range_from_id: from_id,
            range_to_id: to_id,
            triggered_by: None,
            verified_at,
        }));
    };
    let mut hmac_input = Vec::with_capacity(48);
    hmac_input.extend_from_slice(entry.current_hash.as_bytes());
    let id_uuid = entry.id.inner();
    hmac_input.extend_from_slice(id_uuid.as_bytes());
    let expected = HmacSignature::compute(key, &hmac_input);
    // Constant-time tag comparison — a short-circuiting `!=` would leak via
    // timing how many leading bytes of a forged tag matched.
    if !expected.ct_eq(&stored_hmac) {
        return Err(Box::new(ChainVerifyResult {
            outcome: ChainOutcome::HmacMismatch { entry_id: entry.id },
            head_hash: None,
            entries_checked: state.entries_checked,
            anomalies_detected: state.anomalies_detected + 1,
            hmac_checked: false,
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

/// Genesis-anchor check for a full-range pass.
///
/// A complete chain MUST begin at the genesis entry (`seq == 0`, no
/// `prev_hash`). A first entry with a non-zero `seq` or a present `prev_hash`
/// means the genesis prefix was removed — a head-of-log truncation that the
/// tail/seq checks alone would miss. Returns `Some(result)` on failure.
fn check_genesis_anchor(
    entries: &[&AuditEntry],
    log: &AuditLog,
    verified_at: Rfc3339Timestamp,
) -> Option<ChainVerifyResult> {
    let first = entries.first()?;
    if first.seq == 0 && first.prev_hash.is_none() {
        return None;
    }
    Some(ChainVerifyResult {
        outcome: ChainOutcome::GenesisAnchorMissing {
            entry_id: first.id,
            found_seq: first.seq,
        },
        head_hash: log.head().copied(),
        entries_checked: 0,
        anomalies_detected: 1,
        hmac_checked: false,
        range_from_id: None,
        range_to_id: None,
        triggered_by: None,
        verified_at,
    })
}

/// Full-range head-commitment check: truncation followed by pinned-head
/// equality.
///
/// Returns `Some(result)` when the reconstructed tip diverges from the pinned
/// head (truncation or head mismatch); `None` when the head matches and the
/// caller may continue to an `Intact` result. Only meaningful for a full-range
/// pass (both bounds `None`).
fn check_head_commitment(
    state: &WalkState,
    pinned_head: &PinnedHead,
    hmac_key: Option<&[u8; 32]>,
    verified_at: Rfc3339Timestamp,
) -> Option<ChainVerifyResult> {
    let final_head_hash = state.last_hash;
    let final_seq = state.last_seq.unwrap_or(0);

    // Authenticate the pinned head BEFORE trusting head_seq / head_hash. The MAC
    // binds (head_hash, head_seq, head_id, entry_count) under the key, so a
    // pinned head rewritten to look consistent with a truncated log cannot be
    // re-authenticated without the key. entry_count is derived from the pinned
    // head's own claim (head_seq + 1) so the check authenticates the head blob
    // itself; an actual length divergence is then surfaced separately as
    // TruncationDetected below.
    if let Some(key) = hmac_key {
        let entry_count = pinned_head.head_seq.saturating_add(1);
        let expected = pinned_head.compute_head_mac(key, entry_count);
        let authentic = pinned_head
            .hmac_head
            .as_ref()
            .is_some_and(|stored| expected.ct_eq(stored));
        if !authentic {
            return Some(ChainVerifyResult {
                outcome: ChainOutcome::HeadMacMismatch {
                    head_id: pinned_head.head_id,
                },
                head_hash: Some(final_head_hash),
                entries_checked: state.entries_checked,
                anomalies_detected: state.anomalies_detected + 1,
                hmac_checked: false,
                range_from_id: None,
                range_to_id: None,
                triggered_by: None,
                verified_at,
            });
        }
    }

    // Truncation: fewer entries than the pinned head implies.
    if pinned_head.head_seq > final_seq {
        return Some(ChainVerifyResult {
            outcome: ChainOutcome::TruncationDetected {
                last_pinned_seq: pinned_head.head_seq,
                last_actual_seq: final_seq,
            },
            head_hash: Some(final_head_hash),
            entries_checked: state.entries_checked,
            anomalies_detected: state.anomalies_detected + 1,
            hmac_checked: false,
            range_from_id: None,
            range_to_id: None,
            triggered_by: None,
            verified_at,
        });
    }

    // Head commitment: the reconstructed tip MUST match the pinned head exactly
    // (hash and seq). Catches tail-rewrite and truncate-then-re-append attacks
    // that the seq check alone misses.
    if final_head_hash != pinned_head.head_hash || final_seq != pinned_head.head_seq {
        return Some(ChainVerifyResult {
            outcome: ChainOutcome::HeadHashMismatch {
                expected_head: pinned_head.head_hash,
                actual_head: final_head_hash,
            },
            head_hash: Some(final_head_hash),
            entries_checked: state.entries_checked,
            anomalies_detected: state.anomalies_detected + 1,
            hmac_checked: false,
            range_from_id: None,
            range_to_id: None,
            triggered_by: None,
            verified_at,
        });
    }

    None
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

        // HMAC key discipline: an empty slice is an explicit hash-only request;
        // any non-empty slice MUST be exactly 32 bytes. A wrong-length key is a
        // verification failure, never a silent downgrade to hash-only.
        let hmac_key_array: Option<&[u8; 32]> = if hmac_key.is_empty() {
            None
        } else {
            match <&[u8; 32]>::try_from(hmac_key) {
                Ok(k) => Some(k),
                Err(_) => {
                    return ChainVerifyResult {
                        outcome: ChainOutcome::HmacKeyUnavailable,
                        head_hash: log.head().copied(),
                        entries_checked: 0,
                        anomalies_detected: 1,
                        hmac_checked: false,
                        range_from_id: from_id,
                        range_to_id: to_id,
                        triggered_by: None,
                        verified_at,
                    };
                }
            }
        };
        let hmac_checked = hmac_key_array.is_some();

        let entries = slice_entries(log, from_id.as_ref(), to_id.as_ref());

        if entries.is_empty() {
            return ChainVerifyResult {
                outcome: ChainOutcome::Intact,
                head_hash: log.head().copied(),
                entries_checked: 0,
                anomalies_detected: 0,
                // No entry was walked, so no HMAC was actually verified.
                hmac_checked: false,
                range_from_id: from_id,
                range_to_id: to_id,
                triggered_by: None,
                verified_at,
            };
        }

        // Genesis anchor (full-range only): a complete chain MUST begin at the
        // genesis entry (seq == 0, no prev_hash).
        if from_id.is_none() && to_id.is_none() {
            if let Some(result) = check_genesis_anchor(&entries, log, verified_at) {
                return result;
            }
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

        // Head-commitment checks: full-range only (both bounds are None).
        if from_id.is_none() && to_id.is_none() {
            if let Some(result) =
                check_head_commitment(&state, pinned_head, hmac_key_array, verified_at)
            {
                return result;
            }
        }

        ChainVerifyResult {
            outcome: ChainOutcome::Intact,
            head_hash: Some(state.last_hash),
            entries_checked: state.entries_checked,
            anomalies_detected: state.anomalies_detected,
            hmac_checked,
            range_from_id: from_id,
            range_to_id: to_id,
            triggered_by: None,
            verified_at,
        }
    }
}
