//! [`OobNotifier`] driven port — out-of-band confirmation channel.
//!
//! Used by the Access Mediation context to deliver OOB challenges to companion
//! devices and to await operator responses. Adapters target specific transports
//! (push notification, WebSocket relay, local BLE, etc.).

use crate::error::OobError;
use async_trait::async_trait;
use merkle_domain_access_mediation as am;
use merkle_types::ChallengeId;
use std::time::Duration;

/// Driven port for out-of-band challenge delivery and resolution.
#[async_trait]
pub trait OobNotifier: Send + Sync {
    /// Dispatch an OOB challenge to `target_device`.
    ///
    /// The challenge contains an ECIES-encrypted payload per ADR-0019.
    /// Returns `Ok(())` once the challenge has been delivered; does not wait
    /// for operator resolution.
    async fn dispatch(
        &self,
        challenge: &am::oob::challenge::OobChallenge,
        target_device: &am::companion_device::CompanionDevice,
    ) -> Result<(), OobError>;

    /// Await resolution of a previously dispatched challenge.
    ///
    /// Polls or subscribes until the companion device returns a signed
    /// [`OobResolution`](am::oob::resolution::OobResolution) or `timeout`
    /// elapses. Returns [`OobError::Timeout`] on expiry.
    async fn await_resolution(
        &self,
        challenge_id: ChallengeId,
        timeout: Duration,
    ) -> Result<am::oob::resolution::OobResolution, OobError>;

    /// Return `true` if the notifier channel is reachable and ready to dispatch.
    async fn available(&self) -> bool;
}
