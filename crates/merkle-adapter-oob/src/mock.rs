//! In-memory mock implementation of [`OobNotifier`] for testing.
//!
//! [`MockOobNotifier`] allows test authors to pre-load resolutions that will
//! be returned by [`await_resolution`](OobNotifier::await_resolution).
//! Dispatch is always a no-op that returns `Ok(())`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use merkle_domain_access_mediation as am;
use merkle_domain_access_mediation::oob::resolution::OobResolution;
use merkle_ports::error::OobError;
use merkle_ports::OobNotifier;
use merkle_types::{ChallengeId, OobChallengeOutcome};
use parking_lot::Mutex;

/// Pre-loaded resolution store: `ChallengeId` → `OobResolution`.
type ResolutionStore = Mutex<HashMap<ChallengeId, OobResolution>>;

/// Mock [`OobNotifier`] backed by an in-memory store.
///
/// Intended for unit and integration tests only.  All channels always report
/// `available() == true`.  `dispatch` is a no-op.
/// `await_resolution` consumes the pre-loaded entry for the given
/// `challenge_id`, or returns [`OobError::Timeout`] if nothing was pre-loaded.
///
/// # Example
///
/// ```ignore
/// # tokio_test::block_on(async {
/// use std::time::Duration;
/// use merkle_adapter_oob::mock::MockOobNotifier;
/// use merkle_ports::OobNotifier as _;
/// use merkle_types::{ChallengeId, OobChallengeOutcome};
/// use merkle_domain_access_mediation::oob::resolution::OobResolution;
/// use merkle_types::Rfc3339Timestamp;
///
/// let notifier = MockOobNotifier::new();
/// let id: ChallengeId = "018f4c1a-0000-7000-8000-000000000001"
///     .parse()
///     .unwrap();
/// let resolution = OobResolution::new(
///     id.clone(),
///     OobChallengeOutcome::Approved,
///     Some(Rfc3339Timestamp::now()),
///     Some([0u8; 64]),
/// ).unwrap();
/// notifier.preload(id.clone(), resolution);
/// let res = notifier.await_resolution(id, Duration::from_secs(1)).await.unwrap();
/// assert!(res.is_approved());
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct MockOobNotifier {
    store: Arc<ResolutionStore>,
    /// When `true`, `await_resolution` auto-approves any unknown challenge.
    auto_approve: Arc<Mutex<bool>>,
}

impl Default for MockOobNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl MockOobNotifier {
    /// Create a new, empty mock notifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
            auto_approve: Arc::new(Mutex::new(false)),
        }
    }

    /// When enabled, `await_resolution` returns `Approved` for any challenge
    /// that does not have a pre-loaded resolution.
    pub fn set_auto_approve(&self, enabled: bool) {
        *self.auto_approve.lock() = enabled;
    }

    /// Pre-load a resolution that will be returned when
    /// [`await_resolution`](OobNotifier::await_resolution) is called for
    /// `challenge_id`.
    pub fn preload(&self, challenge_id: ChallengeId, resolution: OobResolution) {
        self.store.lock().insert(challenge_id, resolution);
    }

    /// Returns the number of pre-loaded resolutions that have not yet been
    /// consumed.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.store.lock().len()
    }
}

#[async_trait]
impl OobNotifier for MockOobNotifier {
    async fn dispatch(
        &self,
        _challenge: &am::oob::challenge::OobChallenge,
        _target_device: &am::companion_device::CompanionDevice,
    ) -> Result<(), OobError> {
        // Mock: dispatch is always successful, nothing is actually sent.
        Ok(())
    }

    async fn await_resolution(
        &self,
        challenge_id: ChallengeId,
        _timeout: Duration,
    ) -> Result<OobResolution, OobError> {
        if let Some(res) = self.store.lock().remove(&challenge_id) {
            return Ok(res);
        }
        // If auto_approve is enabled, synthesize an Approved resolution.
        if *self.auto_approve.lock() {
            use merkle_types::Rfc3339Timestamp;
            let res = OobResolution::new(
                challenge_id,
                OobChallengeOutcome::Approved,
                Some(Rfc3339Timestamp::now()),
                Some([0u8; 64]),
            )
            .map_err(|e| OobError::Backend(e.to_string()))?;
            return Ok(res);
        }
        Err(OobError::Timeout)
    }

    async fn available(&self) -> bool {
        true
    }
}

/// Builds a minimal `OobResolution` with `outcome=Denied` for test convenience.
#[must_use]
pub fn denied_resolution(challenge_id: ChallengeId) -> OobResolution {
    OobResolution::new(challenge_id, OobChallengeOutcome::Denied, None, None)
        .expect("denied resolution is always valid")
}

/// Builds a minimal `OobResolution` with `outcome=Expired` for test convenience.
#[must_use]
pub fn expired_resolution(challenge_id: ChallengeId) -> OobResolution {
    OobResolution::new(challenge_id, OobChallengeOutcome::Expired, None, None)
        .expect("expired resolution is always valid")
}
