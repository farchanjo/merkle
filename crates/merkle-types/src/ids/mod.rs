//! Typed identifier newtypes — all are `UuidV7` wrappers scoped per entity.

pub mod audit_entry_id;
pub mod challenge_id;
pub mod namespace_id;
pub mod secret_id;
pub mod uuid_v7;

pub use audit_entry_id::AuditEntryId;
pub use challenge_id::ChallengeId;
pub use namespace_id::NamespaceId;
pub use secret_id::SecretId;
pub use uuid_v7::{NIL, UuidV7};
