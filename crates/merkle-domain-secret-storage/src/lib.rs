//! # merkle-domain-secret-storage
//!
//! **Secret Storage** bounded context — the domain core that owns the complete
//! lifecycle of secrets within the vault: creation, versioning, categorization,
//! rotation, and deletion.
//!
//! See `docs/arch/domain/secret-storage.md` for the canonical narrative and
//! `docs/arch/schemas/secret_storage/` for the CUE type shapes.
//!
//! ## DDD role map
//!
//! | Type | DDD role |
//! |---|---|
//! | [`secret::Secret`] | AggregateRoot |
//! | [`namespace::Namespace`] | Entity |
//! | [`secret_version::SecretVersion`] | Entity |
//! | [`private_blob::PrivateBlob`] | ValueObject |
//! | [`public_metadata::PublicMetadata`] | ValueObject |
//! | [`categories::CategoryPayload`] | ValueObject (per-category shape) |
//! | [`retention_policy::RetentionPolicy`] | ValueObject |
//! | [`secret_versioning::SecretVersioning`] | DomainService |
//!
//! ## Key invariants (enforced at the aggregate boundary)
//!
//! 1. A `Handle` uniquely identifies a `Secret` within a `Namespace`.
//! 2. `PrivateBlob` is never returned through the MCP transport without an
//!    explicit Reveal authorized by Operator Confirmation.
//! 3. `sensitivity = High` Secrets must carry at least one `env:*` Tag.
//! 4. Default version retention is 3; older versions are pruned on rotation.
//! 5. FTS5 index covers only public metadata fields; `PrivateBlob` is never
//!    indexed.
//! 6. `category` is immutable after creation.
//! 7. Nonces are unique per encryption call; reuse is a critical fault.
//!
//! ## Cross-context relationships
//!
//! - **CF downstream** from IdentityAndSealing — conforms to `NamespaceDek`
//!   envelope format.
//! - **C/S upstream** to AccessMediation — provides resolved `PrivateBlob`.
//! - **C/S upstream** to BackupRecovery — provides vault state snapshot.
//! - **C/S downstream** from PolicyPermissions — delegates retention / policy.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

pub mod categories;
pub mod error;
pub mod namespace;
pub mod private_blob;
pub mod public_metadata;
pub mod retention_policy;
pub mod secret;
pub mod secret_version;
pub mod secret_versioning;

// Convenience re-exports of the most commonly used types.
pub use categories::CategoryPayload;
pub use error::DomainError;
pub use namespace::Namespace;
pub use private_blob::PrivateBlob;
pub use public_metadata::PublicMetadata;
pub use retention_policy::RetentionPolicy;
pub use secret::Secret;
pub use secret_version::{SecretVersion, SecretVersionId};
pub use secret_versioning::SecretVersioning;
