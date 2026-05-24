//! # merkle-types
//!
//! Foundational ValueObjects shared by all six bounded contexts of Merkle.
//! Mirrors the CUE schemas at `docs/arch/schemas/`.
//!
//! Every type here is a closed, validating wrapper. Construction from an
//! untrusted string MUST go through `FromStr` or `TryFrom<&str>`, which
//! reject malformed input with [`ParseError`].
//!
//! ## Module structure
//!
//! | Module | Contents |
//! |---|---|
//! | [`error`] | `ParseError`, `ValidationError` |
//! | [`ids`] | `UuidV7`, `NamespaceId`, `SecretId`, `AuditEntryId`, `ChallengeId` |
//! | [`hash`] | `Blake3Hash`, `HmacSignature` |
//! | [`time`] | `Rfc3339Timestamp` |
//! | [`handle`] | `Handle` — `vault://<ns>/<cat>/<name>` URI |
//! | [`namespace`] | `NamespaceLabel`, `CategoryName`, `SecretName` |
//! | [`tag`] | `TagKey`, `TagValue`, `Tag` |
//! | [`sensitivity`] | `Sensitivity` — `Low \| Medium \| High` |
//! | [`audit_op`] | `AuditOp` — all 30 auditable operations |
//! | [`audit_outcome`] | `AuditOutcome`, `DenialReason` |
//! | [`security_profile`] | `SecurityProfile` — `Relaxed \| Balanced \| Paranoid` |
//! | [`companion_device`] | `CompanionDeviceClass` — ADR-0020 |
//! | [`oob`] | `OobChannel`, `OobChallengeOutcome` |
//! | [`bounded_context`] | `BoundedContextId` — six bounded contexts |

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

pub mod audit_op;
pub mod audit_outcome;
pub mod bounded_context;
pub mod companion_device;
pub mod error;
pub mod handle;
pub mod hash;
pub mod ids;
pub mod namespace;
pub mod oob;
pub mod security_profile;
pub mod sensitivity;
pub mod tag;
pub mod time;

pub use audit_op::AuditOp;
pub use audit_outcome::{AuditOutcome, DenialReason};
pub use bounded_context::BoundedContextId;
pub use companion_device::CompanionDeviceClass;
pub use error::{ParseError, ValidationError};
pub use handle::Handle;
pub use hash::{Blake3Hash, HmacSignature};
pub use ids::{AuditEntryId, ChallengeId, NamespaceId, SecretId, UuidV7};
pub use namespace::{CategoryName, NamespaceLabel, SecretName};
pub use oob::{OobChallengeOutcome, OobChannel};
pub use security_profile::SecurityProfile;
pub use sensitivity::Sensitivity;
pub use tag::{Tag, TagKey, TagValue};
pub use time::Rfc3339Timestamp;
