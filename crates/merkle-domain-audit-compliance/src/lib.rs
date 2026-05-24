//! # merkle-domain-audit-compliance
//!
//! **Audit and Compliance** bounded context.
//! See `docs/arch/domain/audit-compliance.md` and
//! `docs/arch/schemas/audit_compliance/` for the canonical narrative and
//! CUE type shapes.
//!
//! ## Domain Services
//!
//! - [`AuditWriter`] — appends [`AuditEntry`] records, computes
//!   `current_hash = BLAKE3(canonical_content || prev_hash)` synchronously,
//!   and returns a [`PinnedHead`] snapshot that the caller must persist.
//! - [`ChainVerifier`] — recomputes the hash chain end-to-end and detects
//!   mutation, reordering, gaps, removal, and truncation attacks.
//!
//! ## Read Models
//!
//! - [`AuditQueryModel`] — read-only projections over an [`AuditLog`] snapshot.
//!
//! ## Aggregates / Entities / Value Objects
//!
//! - [`AuditEntry`] — immutable append-only AggregateRoot.
//! - [`AuditLog`] — Entity owning the ordered entry sequence.
//! - [`PinnedHead`] — ValueObject persisted synchronously to `audit_head.json`.
//! - [`AuditQuery`] — ValueObject DSL for querying entries.
//! - [`ChainVerifyResult`] / [`ChainOutcome`] — ValueObjects returned by the
//!   verifier.
//!
//! ## Re-exports from `merkle-types`
//!
//! [`HmacSignature`] is re-exported from [`merkle_types`] as a Shared Kernel
//! artifact co-owned with BackupRecovery (see `docs/arch/domain/context-map.md`).

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

pub mod audit_entry;
pub mod audit_log;
pub mod audit_query;
pub mod chain_verify_result;
pub mod error;
pub mod pinned_head;
pub mod query_model;
pub mod verifier;
pub mod writer;

pub use audit_entry::AuditEntry;
pub use audit_log::AuditLog;
pub use audit_query::AuditQuery;
pub use chain_verify_result::{ChainOutcome, ChainVerifyResult};
pub use error::DomainError;
pub use pinned_head::PinnedHead;
pub use query_model::AuditQueryModel;
pub use verifier::ChainVerifier;
pub use writer::{AppendParams, AuditWriter};

/// Re-export of the Shared Kernel `HmacSignature` from `merkle-types`.
///
/// `HmacSignature` is co-owned by AuditCompliance and BackupRecovery; changes
/// to its shape require joint agreement between both contexts.
pub use merkle_types::HmacSignature;
