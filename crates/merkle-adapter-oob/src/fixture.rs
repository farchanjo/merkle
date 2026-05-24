//! File-backed fixture `OobNotifier` for integration and e2e tests.
//!
//! When the environment variable `MERKLE_OOB_FIXTURE_PATH` is set, the agent
//! replaces the default [`OobNotifierAdapter`](super::OobNotifierAdapter) with
//! this notifier so that tests can inject pre-recorded resolutions without
//! a real companion device.
//!
//! ## Protocol
//!
//! The fixture file contains a single JSON object:
//!
//! ```json
//! {
//!   "challenge_id": "<uuid-v7>",
//!   "outcome": "approved",
//!   "authorized_at": "<rfc3339>",
//!   "device_signature": null
//! }
//! ```
//!
//! `await_resolution` polls the file at 50 ms intervals until either:
//! - A JSON blob is present whose `challenge_id` matches (or is the sentinel
//!   `"00000000-0000-7000-8000-000000000000"` which matches any call), OR
//! - The `timeout` elapses (returns [`OobError::Timeout`]).
//!
//! After the file is consumed the notifier deletes it so successive calls do
//! not re-read a stale resolution.
//!
//! `dispatch` is always a no-op returning `Ok(())`.
//! `available` always returns `true`.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use merkle_domain_access_mediation as am;
use merkle_domain_access_mediation::oob::resolution::OobResolution;
use merkle_ports::error::OobError;
use merkle_ports::OobNotifier;
use merkle_types::{ChallengeId, OobChallengeOutcome, Rfc3339Timestamp};
use serde::Deserialize;
use tracing::{debug, warn};

/// Sentinel `challenge_id` value that matches any `await_resolution` call.
const WILDCARD_CHALLENGE_ID: &str = "00000000-0000-7000-8000-000000000000";

/// Poll interval while waiting for the fixture file to appear.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Raw JSON schema for the fixture file (laxer than `OobResolution`).
#[derive(Debug, Deserialize)]
struct FixtureBlob {
    challenge_id: String,
    outcome: OobChallengeOutcome,
    authorized_at: Option<String>,
}

/// File-backed OOB notifier for e2e and integration tests.
///
/// Reads resolutions from a JSON file at `path` instead of waiting for a real
/// companion device. Intended only for test binaries — do NOT use in
/// production.
#[derive(Debug, Clone)]
pub struct FileFixtureOobNotifier {
    path: PathBuf,
}

impl FileFixtureOobNotifier {
    /// Create a notifier that reads from `path`.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Attempt to read and consume the fixture file.
    ///
    /// Returns `Some(resolution)` when the file exists and contains a blob
    /// whose `challenge_id` matches `target_id` (or is the wildcard).
    /// Deletes the file after a successful read.
    fn try_consume(&self, target_id: &ChallengeId) -> Option<OobResolution> {
        let content = std::fs::read_to_string(&self.path).ok()?;
        let blob: FixtureBlob = serde_json::from_str(&content).ok()?;

        // Accept matching challenge_id or the wildcard sentinel.
        let matches = blob.challenge_id == target_id.to_string()
            || blob.challenge_id == WILDCARD_CHALLENGE_ID;

        if !matches {
            debug!(
                fixture_id = %blob.challenge_id,
                target_id = %target_id,
                "fixture challenge_id does not match — skipping"
            );
            return None;
        }

        // Parse optional authorized_at.
        let authorized_at: Option<Rfc3339Timestamp> = blob
            .authorized_at
            .as_deref()
            .and_then(|s| s.parse().ok());

        let resolution = OobResolution::new(
            *target_id,
            blob.outcome,
            authorized_at,
            None, // device_signature not needed in fixture
        )
        .ok()?;

        // Delete the file so the next call does not re-read a stale entry.
        let _ = std::fs::remove_file(&self.path);
        debug!(challenge_id = %target_id, "fixture OOB resolution consumed");

        Some(resolution)
    }
}

#[async_trait]
impl OobNotifier for FileFixtureOobNotifier {
    async fn dispatch(
        &self,
        challenge: &am::oob::challenge::OobChallenge,
        _target_device: &am::companion_device::CompanionDevice,
    ) -> Result<(), OobError> {
        // No-op in test mode.
        debug!(
            challenge_id = %challenge.challenge_id,
            "FileFixtureOobNotifier: dispatch (no-op)"
        );
        Ok(())
    }

    async fn await_resolution(
        &self,
        challenge_id: ChallengeId,
        timeout: Duration,
    ) -> Result<OobResolution, OobError> {
        let deadline = std::time::Instant::now() + timeout;

        loop {
            if let Some(resolution) = self.try_consume(&challenge_id) {
                return Ok(resolution);
            }

            if std::time::Instant::now() >= deadline {
                warn!(
                    %challenge_id,
                    path = %self.path.display(),
                    "FileFixtureOobNotifier: timeout waiting for fixture file"
                );
                return Err(OobError::Timeout);
            }

            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    async fn available(&self) -> bool {
        true
    }
}
