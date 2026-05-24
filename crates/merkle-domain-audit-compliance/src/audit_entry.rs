//! `AuditEntry` — immutable append-only AggregateRoot.
//!
//! Each entry is a single vault event record. Entries are linked into a
//! BLAKE3 hash chain: `current_hash = BLAKE3(canonical_bytes || prev_hash)`.
//! The genesis entry uses the all-zero sentinel as its `prev_hash`.
//!
//! # Canonical bytes
//!
//! [`AuditEntry::canonical_bytes_for_hashing`] produces a deterministic JSON
//! serialization (sorted keys) of all fields **except** `current_hash` and
//! `hmac`. Those two fields are excluded because they are derived from the
//! canonical bytes themselves.

use serde::{Deserialize, Serialize};

use merkle_types::{
    AuditEntryId, AuditOp, AuditOutcome, Blake3Hash, DenialReason, Handle, HmacSignature,
    NamespaceId, Rfc3339Timestamp, Sensitivity,
};

use crate::error::DomainError;

/// An immutable, append-only record of one vault operation.
///
/// `AuditEntry` is the AggregateRoot of the Audit and Compliance bounded
/// context. Once constructed and appended to an [`crate::AuditLog`] it must
/// never be mutated.  All fields are `pub` because immutability is enforced by
/// the absence of any public mutator — callers obtain entries through
/// [`crate::AuditWriter::append`] and can only read them thereafter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Time-ordered unique identity (UUIDv7).
    pub id: AuditEntryId,
    /// Monotonically increasing sequence number within the log.
    ///
    /// `seq == 0` for the genesis entry. Every subsequent entry increments by
    /// exactly one. Sequence numbers are assigned inside a write-serialized
    /// critical section; no two entries share a number.
    pub seq: u64,
    /// Wall-clock timestamp with microsecond precision (RFC 3339 UTC, `Z` suffix).
    pub ts: Rfc3339Timestamp,
    /// Namespace this operation was performed against.
    pub namespace_id: NamespaceId,
    /// Human-readable program name of the caller (e.g., `"merkle-agent"`).
    pub caller_program: Option<String>,
    /// The auditable operation type (30-value closed enum).
    pub op: AuditOp,
    /// Authorization outcome: `allow`, `deny`, or `error`.
    pub outcome: AuditOutcome,
    /// Free-form denial reason; present only when `outcome == deny`.
    pub denial_reason: Option<DenialReason>,
    /// The opaque vault URI of the secret involved, if applicable.
    pub handle: Option<Handle>,
    /// Sensitivity level of the secret involved, if applicable.
    pub sensitivity: Option<Sensitivity>,
    /// Hash of the immediately preceding entry.
    ///
    /// `None` only for the genesis entry (the very first entry in the chain).
    /// All subsequent entries carry `Some(predecessor.current_hash)`.
    pub prev_hash: Option<Blake3Hash>,
    /// Content-and-chain hash: `BLAKE3(canonical_bytes || prev_hash)`.
    ///
    /// Where `prev_hash` for the genesis entry is the
    /// [`merkle_types::hash::GENESIS`] sentinel (32 zero bytes).
    pub current_hash: Blake3Hash,
    /// BLAKE3-keyed MAC over `current_hash_bytes || id_bytes`.
    ///
    /// Per ADR-0009 Amendment, this MUST be set synchronously at write time
    /// before `fsync`. The field is `Option` only to accommodate the brief
    /// in-flight window before the HMAC is computed; it is always `Some` on
    /// entries that have been persisted.
    pub hmac: Option<HmacSignature>,
}

impl AuditEntry {
    /// Produce the deterministic byte sequence used as input to the hash chain.
    ///
    /// The output is a JSON object with **sorted keys** encoded as UTF-8,
    /// followed by the raw 32 bytes of `prev_hash` (using the genesis sentinel
    /// when `prev_hash` is `None`). The fields `current_hash` and `hmac` are
    /// intentionally excluded.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::CanonicalSerializationFailed`] if JSON
    /// serialization fails (in practice this is infallible for this struct).
    pub fn canonical_bytes_for_hashing(
        &self,
        prev_hash: &Blake3Hash,
    ) -> Result<Vec<u8>, DomainError> {
        // Build an ordered map so key ordering is deterministic regardless of
        // struct field order. serde_json::Map preserves insertion order; we
        // insert in lexicographic key order to match the CUE schema.
        let mut map = serde_json::Map::new();

        // caller_program (optional)
        if let Some(ref prog) = self.caller_program {
            map.insert(
                "caller_program".to_owned(),
                serde_json::Value::String(prog.clone()),
            );
        }

        // denial_reason (optional)
        if let Some(ref dr) = self.denial_reason {
            map.insert(
                "denial_reason".to_owned(),
                serde_json::Value::String(dr.to_string()),
            );
        }

        // handle (optional)
        if let Some(ref h) = self.handle {
            map.insert(
                "handle".to_owned(),
                serde_json::Value::String(h.to_string()),
            );
        }

        // id
        map.insert(
            "id".to_owned(),
            serde_json::Value::String(self.id.to_string()),
        );

        // namespace_id
        map.insert(
            "namespace_id".to_owned(),
            serde_json::Value::String(self.namespace_id.to_string()),
        );

        // op
        map.insert(
            "op".to_owned(),
            serde_json::Value::String(self.op.to_string()),
        );

        // outcome
        map.insert(
            "outcome".to_owned(),
            serde_json::Value::String(self.outcome.to_string()),
        );

        // seq
        map.insert(
            "seq".to_owned(),
            serde_json::Value::Number(serde_json::Number::from(self.seq)),
        );

        // sensitivity (optional)
        if let Some(sens) = self.sensitivity {
            map.insert(
                "sensitivity".to_owned(),
                serde_json::Value::String(sens.to_string()),
            );
        }

        // ts
        map.insert(
            "ts".to_owned(),
            serde_json::Value::String(self.ts.to_string()),
        );

        let json_bytes = serde_json::to_vec(&serde_json::Value::Object(map))?;

        // Append the raw prev_hash bytes so BLAKE3 commits to both content
        // and chain position in a single pass.
        let mut out = json_bytes;
        out.extend_from_slice(prev_hash.as_bytes());
        Ok(out)
    }

    /// Verify the chain link between `self` and the preceding entry `prev`.
    ///
    /// Checks:
    /// 1. `self.seq == prev.seq + 1`
    /// 2. `self.prev_hash == Some(prev.current_hash)`
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::BrokenChainLink`] when the sequence invariant is
    /// violated, or [`DomainError::PrevHashMismatch`] when the hash link is
    /// broken.
    pub fn verify_link(&self, prev: &AuditEntry) -> Result<(), DomainError> {
        let expected_seq = prev.seq + 1;
        if self.seq != expected_seq {
            return Err(DomainError::BrokenChainLink {
                entry_id: self.id,
                expected_seq,
                actual_seq: self.seq,
            });
        }
        if self.prev_hash != Some(prev.current_hash) {
            return Err(DomainError::PrevHashMismatch { entry_id: self.id });
        }
        Ok(())
    }
}
