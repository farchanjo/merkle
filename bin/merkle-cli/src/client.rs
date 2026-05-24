//! Companion Socket client — re-exported from `merkle-companion-client`.
//!
//! All transport logic lives in the shared crate. This module re-exports the
//! public surface so existing `use crate::client::CompanionSocketClient`
//! imports within the CLI continue to compile unchanged.

pub use merkle_companion_client::CompanionSocketClient;
