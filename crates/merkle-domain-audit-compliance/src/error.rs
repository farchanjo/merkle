//! Domain errors for the Audit and Compliance bounded context.

use merkle_types::AuditEntryId;
use thiserror::Error;

/// All errors that can be returned by this bounded context.
#[derive(Debug, Error)]
pub enum DomainError {
    /// The chain link between two consecutive entries is broken.
    ///
    /// Either `seq` is not `prev.seq + 1`, or `prev_hash` does not match
    /// the predecessor's `current_hash`.
    #[error(
        "broken chain link at entry {entry_id}: expected seq {expected_seq}, got {actual_seq}"
    )]
    BrokenChainLink {
        /// The offending entry id.
        entry_id: AuditEntryId,
        /// Expected monotonic sequence number.
        expected_seq: u64,
        /// Actual sequence number stored in the entry.
        actual_seq: u64,
    },

    /// The `prev_hash` on an entry does not match the predecessor's `current_hash`.
    #[error(
        "prev_hash mismatch at entry {entry_id}: \
         stored prev_hash does not equal predecessor current_hash"
    )]
    PrevHashMismatch {
        /// The offending entry id.
        entry_id: AuditEntryId,
    },

    /// The HMAC key supplied has an incorrect length.
    ///
    /// BLAKE3 keyed mode requires exactly 32 bytes.
    #[error("HMAC key must be exactly 32 bytes, got {actual_len}")]
    InvalidHmacKeyLength {
        /// Actual byte length provided.
        actual_len: usize,
    },

    /// JSON serialization failed during canonical-bytes computation.
    #[error("canonical serialization failed: {0}")]
    CanonicalSerializationFailed(#[from] serde_json::Error),

    /// An entry was appended to a non-empty log without a `prev_hash`.
    #[error(
        "genesis entry can only be the first entry; \
         log already has {existing_len} entries"
    )]
    GenesisEntryOnNonEmptyLog {
        /// Number of existing entries in the log.
        existing_len: usize,
    },
}
