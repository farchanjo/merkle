//! `AuditWriter` — DomainService for appending entries to an [`AuditLog`].
//!
//! `AuditWriter` is a stateless service struct. It owns no data; all state
//! lives in the [`AuditLog`] passed by mutable reference. Per ADR-0009
//! Amendment, both the BLAKE3 hash and the HMAC tag are computed **synchronously**
//! before the entry is pushed — no lazy or deferred computation.
//!
//! # Hash computation
//!
//! ```text
//! canonical_bytes = JSON({sorted entry fields except current_hash, hmac}) || prev_hash_bytes
//! current_hash    = BLAKE3(canonical_bytes)
//! hmac            = BLAKE3_keyed(key, current_hash_bytes || id_bytes)
//! ```
//!
//! The genesis entry uses the all-zero `GENESIS` sentinel in place of a real
//! `prev_hash`.

use merkle_types::{
    AuditEntryId, AuditOp, AuditOutcome, Blake3Hash, DenialReason, Handle, HmacSignature,
    NamespaceId, Rfc3339Timestamp, Sensitivity,
    hash::GENESIS,
};

use crate::{
    audit_entry::AuditEntry,
    audit_log::AuditLog,
    error::DomainError,
    pinned_head::PinnedHead,
};

/// All parameters required to append one entry to the audit log.
///
/// Use [`AppendParams::new`] to construct and set optional fields with the
/// builder methods.
///
/// # Example
///
/// ```
/// use merkle_domain_audit_compliance::AppendParams;
/// use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
///
/// let ns = NamespaceId::new();
/// let params = AppendParams::new(AuditOp::Put, AuditOutcome::Allow, ns)
///     .caller_program("merkle-agent");
/// ```
pub struct AppendParams {
    /// The auditable operation type.
    pub op: AuditOp,
    /// Authorization outcome for this operation.
    pub outcome: AuditOutcome,
    /// Free-form denial reason; required when `outcome == Deny`.
    pub denial_reason: Option<DenialReason>,
    /// Namespace this operation was performed against.
    pub namespace_id: NamespaceId,
    /// Human-readable program name of the caller.
    pub caller_program: Option<String>,
    /// The opaque vault URI of the secret involved, if applicable.
    pub handle: Option<Handle>,
    /// Sensitivity level of the secret involved, if applicable.
    pub sensitivity: Option<Sensitivity>,
}

impl AppendParams {
    /// Construct an `AppendParams` with mandatory fields.
    #[must_use]
    pub fn new(op: AuditOp, outcome: AuditOutcome, namespace_id: NamespaceId) -> Self {
        Self {
            op,
            outcome,
            denial_reason: None,
            namespace_id,
            caller_program: None,
            handle: None,
            sensitivity: None,
        }
    }

    /// Set the denial reason.
    #[must_use]
    pub fn denial_reason(mut self, reason: impl Into<DenialReason>) -> Self {
        self.denial_reason = Some(reason.into());
        self
    }

    /// Set the caller program name.
    #[must_use]
    pub fn caller_program(mut self, name: impl Into<String>) -> Self {
        self.caller_program = Some(name.into());
        self
    }

    /// Set the secret handle.
    #[must_use]
    pub fn handle(mut self, h: Handle) -> Self {
        self.handle = Some(h);
        self
    }

    /// Set the sensitivity level.
    #[must_use]
    pub fn sensitivity(mut self, s: Sensitivity) -> Self {
        self.sensitivity = Some(s);
        self
    }
}

/// Stateless append-only writer for the audit hash chain.
///
/// Call [`AuditWriter::append`] to add a new entry. The method computes the
/// BLAKE3 chain link and HMAC synchronously, pushes the entry into the log,
/// and returns a [`PinnedHead`] snapshot that the caller must persist to
/// `audit_head.json` (per ADR-0009 Amendment).
pub struct AuditWriter;

impl AuditWriter {
    /// Append a new [`AuditEntry`] to `log` and return it alongside a
    /// [`PinnedHead`] snapshot.
    ///
    /// The caller is responsible for flushing `pinned_head` to
    /// `audit_head.json` with `O_SYNC` semantics before the enclosing vault
    /// operation is considered complete.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidHmacKeyLength`] when `hmac_key.len() != 32`.
    /// - [`DomainError::CanonicalSerializationFailed`] on JSON serialization
    ///   failure (infallible in practice).
    pub fn append(
        log: &mut AuditLog,
        params: AppendParams,
        hmac_key: &[u8],
    ) -> Result<(AuditEntry, PinnedHead), DomainError> {
        if hmac_key.len() != 32 {
            return Err(DomainError::InvalidHmacKeyLength {
                actual_len: hmac_key.len(),
            });
        }

        // Validated above — infallible.
        let key_array: &[u8; 32] = hmac_key
            .try_into()
            .map_err(|_| DomainError::InvalidHmacKeyLength { actual_len: hmac_key.len() })?;

        let id = AuditEntryId::new();
        let ts = Rfc3339Timestamp::now();

        // Determine seq and prev_hash from the current log head.
        let (seq, prev_hash_field, prev_hash_for_hashing) = match log.head() {
            None => {
                // Genesis entry: seq = 0, no prev_hash field, use GENESIS sentinel.
                (0u64, None, GENESIS)
            }
            Some(&head_hash) => {
                let seq = log.head_seq() + 1;
                (seq, Some(head_hash), head_hash)
            }
        };

        let AppendParams {
            op,
            outcome,
            denial_reason,
            namespace_id,
            caller_program,
            handle,
            sensitivity,
        } = params;

        // Build the partial entry (without current_hash and hmac) so we can
        // call canonical_bytes_for_hashing.
        let partial = AuditEntry {
            id,
            seq,
            ts,
            namespace_id,
            caller_program: caller_program.clone(),
            op,
            outcome,
            denial_reason: denial_reason.clone(),
            handle: handle.clone(),
            sensitivity,
            prev_hash: prev_hash_field,
            // Placeholder — overwritten below after hash computation.
            current_hash: GENESIS,
            hmac: None,
        };

        let canonical = partial.canonical_bytes_for_hashing(&prev_hash_for_hashing)?;
        let current_hash = Blake3Hash::hash(&canonical);

        // HMAC = BLAKE3_keyed(key, current_hash_bytes || id_uuid_bytes)
        let mut hmac_input = Vec::with_capacity(48);
        hmac_input.extend_from_slice(current_hash.as_bytes());
        let id_uuid = id.inner();
        let id_bytes = id_uuid.as_bytes();
        hmac_input.extend_from_slice(id_bytes);
        let hmac = HmacSignature::compute(key_array, &hmac_input);

        let entry = AuditEntry {
            id,
            seq,
            ts,
            namespace_id,
            caller_program,
            op,
            outcome,
            denial_reason,
            handle,
            sensitivity,
            prev_hash: prev_hash_field,
            current_hash,
            hmac: Some(hmac),
        };

        let pinned = PinnedHead::new(current_hash, seq, id, ts);
        log.push(entry.clone());

        Ok((entry, pinned))
    }
}
