//! # merkle-domain-policy-permissions
//!
//! **Policy and Permissions** bounded context.
//!
//! This is the critical policy-decision crate: every Reveal/Put/Use call MUST
//! evaluate against these policies BEFORE side effects. The Rego policies under
//! `docs/arch/policies/` are the executable spec; this crate is the pure-Rust
//! port for fast in-process evaluation.
//!
//! ## Module structure
//!
//! | Module | Contents |
//! |---|---|
//! | [`error`] | `PolicyError` — domain-level error enum |
//! | [`decision`] | `PolicyDecision`, `DenialCode` — allow/deny result |
//! | [`namespace_policy`] | `NamespacePolicy` — AggregateRoot |
//! | [`reveal_policy`] | `RevealPolicy` — ValueObject |
//! | [`rate_limit`] | `RateLimit`, `OpClass`, `RateLimitEntry` — ValueObjects |
//! | [`allowed_consumers`] | `AllowedConsumers` — ValueObject |
//! | [`tags_rules`] | `TagsRules` — ValueObject |
//! | [`retention`] | `RetentionPolicy`, `RetentionStrategy` — ValueObjects |
//! | [`cross_namespace`] | `CrossNamespacePolicy` — ValueObject |
//! | [`unseal_preconditions`] | `UnsealPreconditionsPolicy` — ValueObject |
//! | [`argon2id_floor`] | `Argon2idMinFloor` — ValueObject |
//! | [`device_policy`] | `DevicePolicy` — ValueObject (ADR-0020) |
//! | [`inputs`] | `PolicyDecisionInput`, `SealedState`, `OperatorConfirmationView`, `RateWindowView` |
//! | [`evaluator`] | `PolicyEvaluator` — Domain Service |
//!
//! ## Bounded context isolation
//!
//! This crate intentionally does NOT depend on `merkle-domain-access-mediation`
//! or `merkle-domain-identity`. Types that would otherwise require those
//! dependencies are mirrored locally in [`inputs`] (e.g. `SealedState`,
//! `OperatorConfirmationView`).
//!
//! ## Cross-context relationships
//!
//! - **C/S upstream** to AccessMediation — governs Proxy Tool and Reveal decisions.
//! - **C/S upstream** to SecretStorage — governs NamespacePolicy and retention.
//! - **C/S upstream** to BackupRecovery — supplies scheduling parameters.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod allowed_consumers;
pub mod argon2id_floor;
pub mod cross_namespace;
pub mod decision;
pub mod device_policy;
pub mod error;
pub mod evaluator;
pub mod inputs;
pub mod namespace_policy;
pub mod rate_limit;
pub mod retention;
pub mod reveal_policy;
pub mod tags_rules;
pub mod unseal_preconditions;

// Convenience re-exports of the most-used types.
pub use allowed_consumers::AllowedConsumers;
pub use argon2id_floor::Argon2idMinFloor;
pub use cross_namespace::CrossNamespacePolicy;
pub use decision::{DenialCode, PolicyDecision};
pub use device_policy::DevicePolicy;
pub use error::PolicyError;
pub use evaluator::PolicyEvaluator;
pub use inputs::{OperatorConfirmationView, PolicyDecisionInput, RateWindowView, SealedState};
pub use namespace_policy::NamespacePolicy;
pub use rate_limit::{OpClass, RateLimit, RateLimitEntry};
pub use retention::{RetentionPolicy, RetentionStrategy}; // RetentionStrategy variants: Count, Duration, UntilRevoked
pub use reveal_policy::RevealPolicy;
pub use tags_rules::TagsRules;
pub use unseal_preconditions::{UnsealPreconditionsInput, UnsealPreconditionsPolicy};
