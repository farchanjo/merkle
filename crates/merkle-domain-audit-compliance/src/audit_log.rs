//! `AuditLog` — Entity that owns the ordered sequence of [`AuditEntry`] records.
//!
//! The append-only discipline is enforced by making the only write path
//! `pub(crate)` so that only [`crate::AuditWriter`] (the DomainService) can
//! push entries. External callers receive a shared reference and can only
//! read via [`AuditLog::iter`], [`AuditLog::head`], and [`AuditLog::len`].

use merkle_types::Blake3Hash;

use crate::audit_entry::AuditEntry;

/// An ordered, append-only collection of [`AuditEntry`] records.
///
/// `AuditLog` is the Entity that holds the in-memory representation of the
/// audit hash chain.  The head of the chain is tracked separately so that
/// appending and querying the pinned head are O(1).
///
/// Mutation is restricted to `pub(crate)` so that only [`crate::AuditWriter`]
/// can extend the log.
#[derive(Debug, Default)]
pub struct AuditLog {
    /// Hash of the most recently appended entry, or `None` for an empty log.
    head: Option<Blake3Hash>,
    /// Sequence number of the most recently appended entry (0-based).
    head_seq: u64,
    /// All entries in insertion (ascending sequence) order.
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Create an empty `AuditLog`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the current head hash, or `None` when the log is empty.
    #[must_use]
    pub fn head(&self) -> Option<&Blake3Hash> {
        self.head.as_ref()
    }

    /// Return the sequence number of the current head entry.
    ///
    /// Returns `0` when the log is empty; the first entry has `seq == 0` so
    /// callers should use [`AuditLog::is_empty`] to disambiguate.
    #[must_use]
    pub fn head_seq(&self) -> u64 {
        self.head_seq
    }

    /// Return the number of entries in the log.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` when the log contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all entries in ascending sequence order.
    pub fn iter(&self) -> impl Iterator<Item = &AuditEntry> {
        self.entries.iter()
    }

    /// Push a new entry onto the log.
    ///
    /// This method is `pub(crate)` — only [`crate::AuditWriter`] may call it
    /// so that the chain invariant is maintained by the domain service layer.
    pub(crate) fn push(&mut self, entry: AuditEntry) {
        let seq = entry.seq;
        let hash = entry.current_hash;
        self.head_seq = seq;
        self.head = Some(hash);
        self.entries.push(entry);
    }

    /// Rebuild an `AuditLog` whose head matches a previously persisted
    /// `PinnedHead`, without loading the full entry history into memory.
    ///
    /// Use this at agent boot to restore the seq + head invariants from the
    /// SQLite-backed `audit_entries` table so that subsequent
    /// [`crate::AuditWriter::append`] calls produce monotonic seq values that
    /// don't collide with persisted rows.
    ///
    /// The returned log has no entries in its in-memory `entries` vec — only
    /// the `head` and `head_seq` fields are populated. `iter` and `len` will
    /// therefore reflect the in-process appends only, not the on-disk history.
    /// The chain hash invariant is preserved because every new entry hashes
    /// off the restored head.
    #[must_use]
    pub fn restore_head(head: Blake3Hash, head_seq: u64) -> Self {
        Self {
            head: Some(head),
            head_seq,
            entries: Vec::new(),
        }
    }

    /// Rebuild an `AuditLog` from entries already persisted to storage,
    /// preserving each entry's stored hashes, id, timestamp, and optional
    /// fields exactly.
    ///
    /// This is the ONLY correct way to feed the on-disk chain to
    /// [`crate::ChainVerifier`]. Replaying entries through
    /// [`crate::AuditWriter::append`] recomputes every `current_hash` from fresh
    /// parameters (a new id and timestamp per call) and therefore can never
    /// reproduce the original entries — verification of such a rebuilt log
    /// proves nothing about the persisted chain. Loading the entries verbatim
    /// lets the verifier recompute the canonical bytes and compare against the
    /// genuine stored `current_hash`.
    ///
    /// `entries` MUST be in ascending sequence order (as returned by the
    /// storage adapter's `read_audit`).
    #[must_use]
    pub fn from_persisted(entries: Vec<AuditEntry>) -> Self {
        let head = entries.last().map(|e| e.current_hash);
        let head_seq = entries.last().map_or(0, |e| e.seq);
        Self {
            head,
            head_seq,
            entries,
        }
    }
}
