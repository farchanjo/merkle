//! # merkle-e2e
//!
//! Black-box end-to-end integration tests for the Merkle Vault stack.
//!
//! The tests in `tests/` exercise the full lifecycle:
//!
//! 1. Spawning `merkle-agent` against a temp SQLite DB and temp socket path.
//! 2. Driving `merkle` CLI subcommands (put / list / reveal / audit / doctor).
//! 3. Verifying audit chain integrity — including deliberate tamper detection.
//!
//! Run with:
//!
//! ```text
//! cargo test -p merkle-e2e -- --ignored
//! ```
//!
//! The `--ignored` flag is required because every test is tagged
//! `#[ignore = "requires compiled binaries"]`.
