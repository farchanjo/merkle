//! `AuditBaseline` — ValueObject representing an operator-pinned trust anchor
//! for the audit hash chain (ADR-0029).
//!
//! A baseline records a checkpoint `(baseline_seq, baseline_hash, …)`
//! authenticated under the **current** audit HMAC key. When present, the
//! [`crate::ChainVerifier`] verifies structural (hash-chain) integrity across
//! the whole log but requires HMAC authenticity only from `baseline_seq`
//! forward. This lets a vault that survived a key-provenance incident (a VRK
//! change that poisoned a prefix of entry HMACs) return to a verifiable state
//! without deleting or forging history.
//!
//! The baseline MAC uses a dedicated domain separator so a [`crate::PinnedHead`]
//! head-commitment MAC can never be replayed as a baseline MAC under the same
//! key.

use serde::{Deserialize, Serialize};

use merkle_types::{AuditEntryId, Blake3Hash, HmacSignature, Rfc3339Timestamp};

/// Domain separator bound into every baseline MAC. Distinct from the
/// [`crate::PinnedHead`] head-commitment MAC input so the two tags are not
/// interchangeable under the same key.
const BASELINE_MAC_DOMAIN: &[u8] = b"merkle audit baseline v1";

/// An operator-pinned, key-authenticated trust anchor for the audit chain.
///
/// Persisted as a single-row record (mirrors [`crate::PinnedHead`]). Written by
/// the re-baseline application command after an operator confirms it; consumed
/// by [`crate::ChainVerifier::verify_from_baseline`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditBaseline {
    /// Sequence number of the anchor entry (the trust floor for HMAC checks).
    pub baseline_seq: u64,
    /// Identity of the anchor entry.
    pub baseline_id: AuditEntryId,
    /// `current_hash` of the anchor entry. Via the hash chain this commits to
    /// the entire prefix beneath it, so a structural walk can confirm the
    /// prefix was not mutated even though its HMAC tags are not authenticated.
    pub baseline_hash: Blake3Hash,
    /// Number of entries the chain committed to when the baseline was pinned
    /// (`baseline_seq + 1` for a gap-free chain).
    pub entry_count: u64,
    /// Free-form operator note explaining why the baseline was pinned.
    pub reason: String,
    /// Wall-clock UTC timestamp when this baseline was recorded.
    pub created_at: Rfc3339Timestamp,
    /// Authentication tag over
    /// `DOMAIN || baseline_hash || baseline_seq || baseline_id || entry_count`.
    ///
    /// Computed by [`AuditBaseline::with_mac`] under the current audit HMAC key.
    /// `None` only for records built before a key is attached; the verifier
    /// treats a `None` tag as authentication failure (fail-closed).
    #[serde(default)]
    pub hmac: Option<HmacSignature>,
}

impl AuditBaseline {
    /// Construct a baseline snapshot without an authentication tag.
    ///
    /// Call [`AuditBaseline::with_mac`] to bind the tag under a key.
    #[must_use]
    pub fn new(
        baseline_seq: u64,
        baseline_id: AuditEntryId,
        baseline_hash: Blake3Hash,
        entry_count: u64,
        reason: String,
        created_at: Rfc3339Timestamp,
    ) -> Self {
        Self {
            baseline_seq,
            baseline_id,
            baseline_hash,
            entry_count,
            reason,
            created_at,
            hmac: None,
        }
    }

    /// Recompute the baseline MAC under `key`.
    ///
    /// The verifier recomputes this with the same inputs to authenticate the
    /// baseline before trusting `baseline_seq` / `baseline_hash`.
    #[must_use]
    pub fn compute_mac(&self, key: &[u8; 32]) -> HmacSignature {
        let mut input = Vec::with_capacity(96);
        input.extend_from_slice(BASELINE_MAC_DOMAIN);
        input.extend_from_slice(self.baseline_hash.as_bytes());
        input.extend_from_slice(&self.baseline_seq.to_le_bytes());
        input.extend_from_slice(self.baseline_id.inner().as_bytes());
        input.extend_from_slice(&self.entry_count.to_le_bytes());
        HmacSignature::compute(key, &input)
    }

    /// Attach the authenticated baseline MAC, consuming `self`.
    #[must_use]
    pub fn with_mac(mut self, key: &[u8; 32]) -> Self {
        self.hmac = Some(self.compute_mac(key));
        self
    }

    /// Return `true` when the stored tag authenticates under `key`.
    ///
    /// Uses a constant-time comparison and fails closed when no tag is present.
    #[must_use]
    pub fn verify_mac(&self, key: &[u8; 32]) -> bool {
        self.hmac
            .as_ref()
            .is_some_and(|stored| self.compute_mac(key).ct_eq(stored))
    }
}

#[cfg(test)]
mod tests {
    use super::AuditBaseline;
    use merkle_types::{AuditEntryId, Blake3Hash, Rfc3339Timestamp, hash::GENESIS};

    const KEY: [u8; 32] = [0x42; 32];
    const OTHER: [u8; 32] = [0x11; 32];

    fn sample() -> AuditBaseline {
        AuditBaseline::new(
            7,
            AuditEntryId::new(),
            Blake3Hash::hash(b"anchor"),
            8,
            "recovery: quarantine pre-rotation prefix".to_owned(),
            Rfc3339Timestamp::now(),
        )
    }

    #[test]
    fn mac_round_trips_under_the_pinning_key() {
        let b = sample().with_mac(&KEY);
        assert!(
            b.verify_mac(&KEY),
            "baseline must authenticate under its key"
        );
    }

    #[test]
    fn mac_fails_under_a_different_key() {
        let b = sample().with_mac(&KEY);
        assert!(!b.verify_mac(&OTHER), "wrong key must not authenticate");
    }

    #[test]
    fn unsigned_baseline_fails_closed() {
        assert!(
            !sample().verify_mac(&KEY),
            "a baseline with no tag must never authenticate"
        );
    }

    #[test]
    fn mac_binds_every_field() {
        let base = sample().with_mac(&KEY);
        // Flipping any committed field must invalidate the tag carried over.
        let mut tampered = base.clone();
        tampered.baseline_seq = base.baseline_seq + 1;
        assert!(!tampered.verify_mac(&KEY), "seq is bound into the MAC");
        let mut tampered = base.clone();
        tampered.baseline_hash = GENESIS;
        assert!(!tampered.verify_mac(&KEY), "hash is bound into the MAC");
        let mut tampered = base;
        tampered.entry_count += 1;
        assert!(
            !tampered.verify_mac(&KEY),
            "entry_count is bound into the MAC"
        );
    }
}
