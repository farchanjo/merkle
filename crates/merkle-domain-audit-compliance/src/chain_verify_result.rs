//! `ChainVerifyResult` and `ChainOutcome` — ValueObjects returned by
//! [`crate::ChainVerifier`].
//!
//! Mirrors `#VerifyResult` in `docs/arch/schemas/audit_compliance/chain_verifier.cue`
//! with the extended ADR-0009 Amendment fields (truncation detection).

use merkle_types::{AuditEntryId, Blake3Hash, Rfc3339Timestamp};

/// The coarse outcome of a chain verification pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainOutcome {
    /// Every entry's hash link and HMAC (when a key is supplied) is valid.
    Intact,

    /// A hash-link discontinuity was found at the given entry.
    BrokenAtEntry {
        /// The entry where the break was first detected.
        broken_at_id: AuditEntryId,
        /// The `prev_hash` value that was expected (predecessor's `current_hash`).
        expected_prev: Blake3Hash,
        /// The `prev_hash` value actually stored in the entry (`None` when the
        /// entry has no `prev_hash` but a predecessor exists).
        actual_prev: Option<Blake3Hash>,
    },

    /// An entry's stored HMAC tag does not match the recomputed tag.
    HmacMismatch {
        /// The entry whose HMAC failed verification.
        entry_id: AuditEntryId,
    },

    /// A verification key was supplied but the entry carries no HMAC tag.
    ///
    /// A keyed verification pass MUST authenticate every entry. An entry whose
    /// `hmac` is `None` while a key is present cannot be authenticated, so it is
    /// a verification failure rather than a silently-skipped check. Persisting a
    /// `NULL` tag is additionally blocked at the storage layer (`hmac` is
    /// `NOT NULL`), so this outcome flags an in-memory or out-of-band tamper.
    MissingHmac {
        /// The entry that is missing its HMAC tag.
        entry_id: AuditEntryId,
    },

    /// A full-range pass did not begin at the genesis anchor.
    ///
    /// The first entry of a complete chain MUST have `seq == 0` and no
    /// `prev_hash` (it hashes against the [`merkle_types::hash::GENESIS`]
    /// sentinel). A first entry with a non-zero `seq` or a present `prev_hash`
    /// indicates the genesis prefix was removed — a head-of-log truncation that
    /// the tail-oriented seq/head checks would otherwise miss.
    GenesisAnchorMissing {
        /// The first entry actually present in the full-range pass.
        entry_id: AuditEntryId,
        /// The `seq` of that first entry (non-zero signals a removed prefix).
        found_seq: u64,
    },

    /// The pinned head's authentication tag does not match the recomputed MAC.
    ///
    /// The [`crate::PinnedHead`] carries an HMAC over
    /// `head_hash || head_seq || head_id || entry_count`. On a keyed full-range
    /// pass the verifier recomputes this MAC and rejects the pinned head when it
    /// fails (or is absent) **before** trusting `head_seq`/`head_hash`. Catches
    /// truncate-then-rewrite-pinned-head attacks where the head fields are made
    /// internally consistent with a shortened log but cannot be re-authenticated
    /// without the key.
    HeadMacMismatch {
        /// The pinned head's claimed head entry id.
        head_id: AuditEntryId,
    },

    /// The log has fewer entries than the pinned head implies.
    ///
    /// Detected when the last entry's `seq` is less than the pinned head's
    /// `head_seq`, which indicates that one or more tail entries were removed.
    TruncationDetected {
        /// `seq` of the last entry recorded in the pinned head.
        last_pinned_seq: u64,
        /// `seq` of the last entry actually present in the log.
        last_actual_seq: u64,
    },

    /// The reconstructed chain head does not match the pinned head commitment.
    ///
    /// Detected on a full-range pass when the last entry's `current_hash` (or
    /// its `seq`) differs from the synchronously-persisted [`crate::PinnedHead`].
    /// Catches tail-rewrite and truncate-then-re-append attacks that preserve
    /// the entry count but change the true chain tip. The pinned `head_hash` is
    /// the cryptographic witness of the genuine tip and must match exactly.
    HeadHashMismatch {
        /// `head_hash` recorded in the pinned head (the expected tip).
        expected_head: Blake3Hash,
        /// `current_hash` of the last entry actually present in the log.
        actual_head: Blake3Hash,
    },

    /// An HMAC key was supplied but is not exactly 32 bytes.
    ///
    /// Verification refuses to silently downgrade to a hash-only check: a
    /// malformed key is treated as a verification failure, never as
    /// "no key requested". Callers that genuinely want a hash-only pass must
    /// pass an empty key slice.
    HmacKeyUnavailable,

    /// An entry could not be canonicalized for hashing during verification.
    ///
    /// A serialization failure on the audit path is itself an integrity
    /// anomaly — the entry can no longer be proven to commit to its hash — so
    /// it fails verification rather than being silently skipped.
    EntrySerializationFailed {
        /// The entry that failed canonical serialization.
        entry_id: AuditEntryId,
    },
}

/// Full result of a [`crate::ChainVerifier`] pass.
///
/// Mirrors `#VerifyResult` in `chain_verifier.cue` with truncation-detection
/// fields added per ADR-0009 Amendment.
#[derive(Debug, Clone)]
pub struct ChainVerifyResult {
    /// Coarse outcome of the verification pass.
    pub outcome: ChainOutcome,
    /// Hash of the final entry in the verified range (`None` for an empty log).
    pub head_hash: Option<Blake3Hash>,
    /// Number of entries examined during the pass.
    pub entries_checked: u64,
    /// Count of structural anomalies found (0 when `outcome == Intact`).
    pub anomalies_detected: u32,
    /// Whether the keyed HMAC tag was actually verified on every entry in the
    /// range. `false` means the pass was hash-only (no key supplied, an empty
    /// range, or a non-`Intact` outcome) — callers MUST NOT treat a hash-only
    /// `Intact` as a full tamper-evidence guarantee.
    pub hmac_checked: bool,
    /// First entry in the verified range (`None` for a full-log pass).
    pub range_from_id: Option<AuditEntryId>,
    /// Last entry in the verified range (`None` for a full-log pass).
    pub range_to_id: Option<AuditEntryId>,
    /// Identifier of the subsystem that initiated this verification run.
    ///
    /// Well-known values: `"doctor"`, `"remote_sync"`, `"boot"`, `"restore"`.
    pub triggered_by: Option<String>,
    /// Timestamp when this verification pass completed.
    pub verified_at: Rfc3339Timestamp,
}

impl ChainVerifyResult {
    /// Return `true` when the chain is intact (no anomalies detected).
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.outcome == ChainOutcome::Intact
    }
}
