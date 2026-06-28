//! `PinnedHead` — ValueObject representing the chain head persisted to
//! `audit_head.json`.
//!
//! Per ADR-0009 Amendment, after every successful audit entry append the agent
//! MUST write this value synchronously (O_SYNC / `sync_all`) to
//! `audit_head.json` in the same directory as `audit.jsonl`. The Chain
//! Verifier compares its reconstructed head against this value to detect
//! truncation attacks.

use serde::{Deserialize, Serialize};

use merkle_types::{AuditEntryId, Blake3Hash, HmacSignature, Rfc3339Timestamp};

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
    /// Authentication tag over `head_hash || head_seq || head_id || entry_count`.
    ///
    /// Computed by [`PinnedHead::with_head_mac`] in
    /// [`crate::AuditWriter::append`] so the pinned head cannot be rewritten to
    /// match a truncated log without the HMAC key. `None` only for heads built
    /// by recovery/legacy paths that lack a key; the verifier treats a `None`
    /// tag on a keyed pass as a failure (fail-closed).
    #[serde(default)]
    pub hmac_head: Option<HmacSignature>,
}

impl PinnedHead {
    /// Construct a `PinnedHead` snapshot from the components of the last
    /// appended entry.
    ///
    /// The authentication tag is left unset; call [`PinnedHead::with_head_mac`]
    /// to bind it under a key.
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
            hmac_head: None,
        }
    }

    /// Recompute the head-commitment MAC for this pinned head under `key`.
    ///
    /// Binds `head_hash`, `head_seq`, `head_id`, and `entry_count` into a single
    /// BLAKE3-keyed tag. The verifier recomputes this with the same inputs to
    /// authenticate the pinned head before trusting its fields.
    #[must_use]
    pub fn compute_head_mac(&self, key: &[u8; 32], entry_count: u64) -> HmacSignature {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(self.head_hash.as_bytes());
        input.extend_from_slice(&self.head_seq.to_le_bytes());
        input.extend_from_slice(self.head_id.inner().as_bytes());
        input.extend_from_slice(&entry_count.to_le_bytes());
        HmacSignature::compute(key, &input)
    }

    /// Attach the authenticated head-commitment MAC, consuming `self`.
    ///
    /// `entry_count` is the total number of entries the chain commits to
    /// (`head_seq + 1` for a gap-free chain). Used by
    /// [`crate::AuditWriter::append`] on the write path.
    #[must_use]
    pub fn with_head_mac(mut self, key: &[u8; 32], entry_count: u64) -> Self {
        self.hmac_head = Some(self.compute_head_mac(key, entry_count));
        self
    }
}
