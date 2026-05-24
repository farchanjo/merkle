//! [`OobFixture`] — pre-record OOB resolutions for e2e tests.
//!
//! The fixture writes an `OobResolution`-compatible JSON blob to a temporary
//! file.  When the agent is started with `MERKLE_OOB_FIXTURE_PATH` pointing at
//! that file, the `FileFixtureOobNotifier` reads the resolution and returns it
//! instead of waiting for a real companion device.
#![allow(dead_code)]


use std::path::{Path, PathBuf};

use anyhow::Context as _;
use merkle_types::OobChallengeOutcome;
use serde::{Deserialize, Serialize};

/// Serializable representation of a pre-recorded OOB resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureResolution {
    /// UUIDv7 of the challenge being resolved (or the wildcard sentinel).
    pub challenge_id: String,
    /// Outcome for the fixture: `Approved`, `Denied`, or `Expired`.
    pub outcome: OobChallengeOutcome,
    /// RFC 3339 timestamp when the operator acknowledged.
    pub authorized_at: Option<String>,
}

/// Manages the OOB fixture file for a single agent lifetime.
pub struct OobFixture {
    path: PathBuf,
}

impl OobFixture {
    /// Create a fixture manager targeting `path`.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Write a pre-approved resolution that matches any challenge (wildcard).
    ///
    /// The agent's `FileFixtureOobNotifier` accepts the wildcard challenge_id
    /// `"00000000-0000-7000-8000-000000000000"` for any call to
    /// `await_resolution`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn preload_approved(&self, challenge_id: &str) -> anyhow::Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let resolution = FixtureResolution {
            challenge_id: challenge_id.to_owned(),
            outcome: OobChallengeOutcome::Approved,
            authorized_at: Some(now),
        };
        let json = serde_json::to_string_pretty(&resolution).context("serialize fixture")?;
        std::fs::write(&self.path, json)
            .with_context(|| format!("write fixture to {}", self.path.display()))
    }

    /// Returns the path the agent reads from.
    pub fn path(&self) -> &Path {
        &self.path
    }
}
