//! `AuditQuery` — ValueObject representing a filter over the audit log.
//!
//! All fields are optional; omitting a field means "match all". Queries are
//! evaluated by [`crate::AuditQueryModel`].

use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId, Rfc3339Timestamp, Sensitivity};

/// A structured filter for reading entries from an [`crate::AuditLog`].
///
/// Build with direct struct construction; all fields default to `None`
/// (match-all). Apply with [`crate::AuditQueryModel::execute`].
///
/// # Example
///
/// ```
/// use merkle_domain_audit_compliance::AuditQuery;
/// use merkle_types::AuditOutcome;
///
/// let q = AuditQuery {
///     outcome: Some(AuditOutcome::Deny),
///     limit: Some(50),
///     ..AuditQuery::default()
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Filter by operation type.
    pub op: Option<AuditOp>,
    /// Filter by outcome.
    pub outcome: Option<AuditOutcome>,
    /// Filter by namespace identifier.
    pub namespace_id: Option<NamespaceId>,
    /// Filter by secret handle.
    pub handle: Option<Handle>,
    /// Filter by sensitivity level.
    pub sensitivity: Option<Sensitivity>,
    /// Inclusive lower bound on the entry timestamp.
    pub from: Option<Rfc3339Timestamp>,
    /// Inclusive upper bound on the entry timestamp.
    pub to: Option<Rfc3339Timestamp>,
    /// Maximum number of entries to return.
    pub limit: Option<u32>,
}
