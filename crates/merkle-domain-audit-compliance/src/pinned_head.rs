//! `PinnedHead` — ValueObject representing the chain head persisted to
//! `audit_head.json`.
//!
//! Per ADR-0009 Amendment, after every successful audit entry append the agent
//! MUST write this value synchronously (O_SYNC / `sync_all`) to
//! `audit_head.json` in the same directory as `audit.jsonl`. The Chain
//! Verifier compares its reconstructed head against this value to detect
//! truncation attacks.

use serde::{Deserialize, Serialize};

use merkle_types::{AuditEntryId, Blake3Hash, Rfc3339Timestamp};

/// The persisted chain-head snapshot.
///
/// Written synchronously after every successful [`crate::AuditWriter::append`]
/// call to provide a truncation-attack witness that cannot be forged without
/// the HMAC key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedHead {
    /// `current_hash` of the most recently appended entry.
    pub head_hash: Blake3Hash,
    /// Sequence number of the most recently appended entry.
    pub head_seq: u64,
    /// Identity of the most recently appended entry.
    pub head_id: AuditEntryId,
    /// Wall-clock UTC timestamp when this head was recorded.
    pub updated_at: Rfc3339Timestamp,
}

impl PinnedHead {
    /// Construct a `PinnedHead` snapshot from the components of the last
    /// appended entry.
    #[must_use]
    pub fn new(
        head_hash: Blake3Hash,
        head_seq: u64,
        head_id: AuditEntryId,
        updated_at: Rfc3339Timestamp,
    ) -> Self {
        Self {
            head_hash,
            head_seq,
            head_id,
            updated_at,
        }
    }
}
