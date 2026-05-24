//! Test harness utilities for e2e tests.
//!
//! Provides:
//! - [`AgentProcessHandle`] — spawn/poll/kill the `merkle-agent` daemon.
//! - [`CliRunner`] / [`CliOutput`] — run `merkle` CLI against a socket path.
//! - [`OobFixture`] — inject pre-recorded OOB resolutions via a temp file.
#![allow(dead_code)]


pub mod agent_handle;
pub mod cli;
pub mod oob_fixture;

pub use agent_handle::AgentProcessHandle;
pub use cli::CliRunner;
