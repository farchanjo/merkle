//! # merkle-companion-client
//!
//! Reusable HTTP/1.1 client for the Merkle Vault Agent **Companion Socket**.
//!
//! The Vault Agent exposes its only driving port as an HTTP/1.1 API over a
//! Unix domain socket (UDS). This crate provides:
//!
//! - [`transport`] — [`UnixConnector`](transport::UnixConnector) and
//!   [`UnixStreamWrapper`](transport::UnixStreamWrapper) that bridge Tokio's
//!   async I/O to hyper's transport traits.
//! - [`client`] — [`CompanionSocketClient`](client::CompanionSocketClient)
//!   with generic `get` / `post` / `delete` helpers **and** typed wrappers for
//!   all 19 Companion Socket endpoints.
//! - [`error`] — [`ClientError`](error::ClientError) enum; all client methods
//!   return `Result<_, ClientError>`.
//!
//! ## Re-exports
//!
//! All DTO types from
//! [`merkle_companion_contract`] are re-exported for consumer
//! convenience so callers need not add `merkle-adapter-companion-socket` as a
//! direct dependency.
//!
//! ## Architecture note
//!
//! Per ADR-0002 the Companion Socket is the **sole driving port** of the Vault
//! Agent domain. Both the CLI (`merkle-cli`) and the MCP Adapter
//! (`merkle-mcp`) communicate exclusively through this client; neither may
//! import from `merkle-application` directly.

pub mod client;
pub mod error;
pub mod transport;

pub use client::{CompanionSocketClient, RevealOutcome};
pub use error::{ClientError, ProblemDetail};

/// Re-exported DTOs from [`merkle_companion_contract`].
///
/// Consumers can import DTO types directly from this crate without depending on
/// `merkle-adapter-companion-socket`.
pub mod dto {
    pub use merkle_companion_contract::*;
}
