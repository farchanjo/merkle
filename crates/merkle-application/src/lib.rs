//! # merkle-application
//!
//! Application layer — use cases and command handlers that orchestrate the
//! six domain bounded contexts through hexagonal port traits.
//!
//! ## Design contract
//!
//! - No infrastructure imports: depends only on `merkle-domain-*` and
//!   `merkle-ports`. Adapter crates are wired at the binary entry point.
//! - All handlers are `async fn execute(&self, ctx: &AppContext)` — they never
//!   own state beyond the inputs they were constructed with.
//! - `AppContext` is an `Arc`-filled handle bag; it is cheaply cloned for
//!   driving adapters that need to share it across tasks.
//! - Commands return a typed `Output` struct; queries follow the same
//!   convention so the CQRS boundary is explicit at the type level.
//!
//! ## Module structure
//!
//! | Module | Contents |
//! |---|---|
//! | [`context`] | `AppContext` — shared handles to all driven ports |
//! | [`error`] | `AppError` — unified error enum |
//! | [`commands`] | Write-side handlers (one module per use case) |
//! | [`queries`] | Read-side handlers (one module per query) |
//! | [`prelude`] | Convenience re-exports for driving adapters |

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod commands;
pub mod context;
pub mod error;
pub mod jwt_verifier;
pub mod prelude;
pub mod queries;
pub mod value_format;

pub use context::AppContext;
pub use error::AppError;
pub use value_format::ValueFormat;

/// Re-export of the audit-chain verdict enum, surfaced through
/// [`queries::verify_chain::VerifyChainOutput`] so downstream consumers (the
/// daemon's background verifier, diagnostics) can match on the outcome without
/// depending on the audit-compliance domain crate directly.
pub use merkle_domain_audit_compliance::ChainOutcome;
