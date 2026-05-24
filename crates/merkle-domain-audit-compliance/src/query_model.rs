//! `AuditQueryModel` — read-only projection over an [`AuditLog`] snapshot.
//!
//! The query model provides filtering over the in-memory log. It holds a
//! shared reference to an `AuditLog` so that it cannot outlive it, and it
//! exposes no mutation path.

use crate::{audit_entry::AuditEntry, audit_log::AuditLog, audit_query::AuditQuery};

/// Read-only projection over an [`AuditLog`].
///
/// Construct with [`AuditQueryModel::new`], then call [`AuditQueryModel::execute`]
/// to evaluate an [`AuditQuery`] filter. Results are returned in ascending
/// sequence order (insertion order of the underlying log).
///
/// # Example
///
/// ```
/// use merkle_domain_audit_compliance::{AuditLog, AuditQuery, AuditQueryModel};
/// use merkle_types::AuditOutcome;
///
/// let log = AuditLog::new();
/// let model = AuditQueryModel::new(&log);
/// let results = model.execute(&AuditQuery {
///     outcome: Some(AuditOutcome::Deny),
///     ..AuditQuery::default()
/// });
/// assert!(results.is_empty()); // empty log
/// ```
pub struct AuditQueryModel<'a> {
    log: &'a AuditLog,
}

impl<'a> AuditQueryModel<'a> {
    /// Construct a read-only projection over `log`.
    #[must_use]
    pub fn new(log: &'a AuditLog) -> Self {
        Self { log }
    }

    /// Evaluate `query` and return matching entries in ascending sequence order.
    ///
    /// All filter fields are combined with logical AND. An empty query (all
    /// fields `None`) returns all entries, subject to the `limit`.
    #[must_use]
    pub fn execute(&self, query: &AuditQuery) -> Vec<&'a AuditEntry> {
        let iter = self.log.iter().filter(|e| Self::matches(e, query));

        match query.limit {
            Some(n) => iter.take(n as usize).collect(),
            None => iter.collect(),
        }
    }

    fn matches(entry: &AuditEntry, q: &AuditQuery) -> bool {
        if let Some(op) = q.op {
            if entry.op != op {
                return false;
            }
        }
        if let Some(outcome) = q.outcome {
            if entry.outcome != outcome {
                return false;
            }
        }
        if let Some(ref ns) = q.namespace_id {
            if &entry.namespace_id != ns {
                return false;
            }
        }
        if let Some(ref handle) = q.handle {
            if entry.handle.as_ref() != Some(handle) {
                return false;
            }
        }
        if let Some(sensitivity) = q.sensitivity {
            if entry.sensitivity != Some(sensitivity) {
                return false;
            }
        }
        if let Some(from) = q.from {
            if entry.ts < from {
                return false;
            }
        }
        if let Some(to) = q.to {
            if entry.ts > to {
                return false;
            }
        }
        true
    }
}
