//! # merkle-adapter-oob
//!
//! **Driven-port adapter** — OOB (Out-of-Band) Confirmation delivery.
//!
//! Implements [`merkle_ports::OobNotifier`] for each of the three
//! confirmation channels defined in ADR-0011:
//!
//! | Module | Channel | Phase |
//! |---|---|---|
//! | [`desktop_notif`] | OS desktop notification (macOS/Linux/Windows) | Phase 5 |
//! | [`terminal_prompt`] | TTY key-press prompt on `/dev/tty` | Minimal impl |
//! | [`localhost_confirm`] | Localhost browser confirmation page | Phase 5 |
//! | [`mock`] | In-memory mock for tests | Complete |
//!
//! [`OobNotifierAdapter`] is the dispatcher: it holds an ordered list of
//! channel implementations and routes each [`OobChallenge`] to the channel
//! identified by its [`merkle_types::OobChannel`] variant.
//!
//! ## Pending challenge registry
//!
//! [`pending::PendingChallengeRegistry`] provides the in-memory rendezvous
//! between `dispatch` (which registers a challenge) and `await_resolution`
//! (which waits for the companion device or operator to respond).
//!
//! ## ADR references
//!
//! - [ADR-0011](../../../docs/arch/adr/0011-slash-only-reveal-with-oob-for-high-sensitivity.md)
//!   — Two-flag Operator Confirmation model; OOB channel options.
//! - [ADR-0019](../../../docs/arch/adr/0019-ecies-encryption-for-oob-challenge-payload.md)
//!   — ECIES encryption of the OOB challenge payload.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod desktop_notif;
pub mod fixture;
pub mod localhost_confirm;
pub mod mock;
pub mod pending;
pub mod terminal_prompt;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use merkle_domain_access_mediation as am;
use merkle_domain_access_mediation::oob::resolution::OobResolution;
use merkle_ports::OobNotifier;
use merkle_ports::error::OobError;
use merkle_types::{ChallengeId, OobChannel};
use tracing::{debug, warn};

/// Dispatcher that routes each [`OobChallenge`] to the correct channel
/// implementation based on [`OobChannel`].
///
/// Holds one channel per [`OobChannel`] variant.  If a channel reports
/// `available() == false`, the corresponding variant returns
/// [`OobError::Unavailable`].
pub struct OobNotifierAdapter {
    desktop: Arc<dyn OobNotifier>,
    terminal: Arc<dyn OobNotifier>,
    localhost: Arc<dyn OobNotifier>,
}

impl std::fmt::Debug for OobNotifierAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OobNotifierAdapter")
            .field("desktop", &"<dyn OobNotifier>")
            .field("terminal", &"<dyn OobNotifier>")
            .field("localhost", &"<dyn OobNotifier>")
            .finish()
    }
}

impl OobNotifierAdapter {
    /// Construct an adapter with the given channel implementations.
    ///
    /// Pass concrete channel structs (or mocks) for each variant.
    pub fn new(
        desktop: Arc<dyn OobNotifier>,
        terminal: Arc<dyn OobNotifier>,
        localhost: Arc<dyn OobNotifier>,
    ) -> Self {
        Self {
            desktop,
            terminal,
            localhost,
        }
    }

    /// Construct an adapter using the default skeletal implementations for
    /// all three channels.
    ///
    /// Useful for production wiring before Phase 5 channel implementations
    /// are complete.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(
            Arc::new(desktop_notif::DesktopNotifChannel::new()),
            Arc::new(terminal_prompt::TerminalPromptChannel::new()),
            Arc::new(localhost_confirm::LocalhostConfirmChannel::new()),
        )
    }

    fn channel_for(&self, oob_channel: OobChannel) -> &dyn OobNotifier {
        match oob_channel {
            OobChannel::DesktopNotif => self.desktop.as_ref(),
            OobChannel::TerminalPrompt => self.terminal.as_ref(),
            OobChannel::LocalhostConfirm => self.localhost.as_ref(),
        }
    }
}

#[async_trait]
impl OobNotifier for OobNotifierAdapter {
    async fn dispatch(
        &self,
        challenge: &am::oob::challenge::OobChallenge,
        target_device: &am::companion_device::CompanionDevice,
    ) -> Result<(), OobError> {
        let ch = self.channel_for(challenge.oob_channel);

        if !ch.available().await {
            warn!(
                channel = %challenge.oob_channel,
                challenge_id = %challenge.challenge_id,
                "OOB channel unavailable",
            );
            return Err(OobError::Unavailable);
        }

        debug!(
            channel = %challenge.oob_channel,
            challenge_id = %challenge.challenge_id,
            "dispatching OOB challenge",
        );
        ch.dispatch(challenge, target_device).await
    }

    async fn await_resolution(
        &self,
        challenge_id: ChallengeId,
        _timeout: Duration,
    ) -> Result<OobResolution, OobError> {
        // The adapter cannot know which channel owns the pending challenge
        // without additional bookkeeping.  For Phase 3 the caller is expected
        // to use the channel directly (or the mock).  A future phase will
        // route via a shared PendingChallengeRegistry.
        //
        // TODO(Phase 5): maintain a shared registry keyed by ChallengeId so
        // the adapter can route await_resolution to the correct channel.
        warn!(
            %challenge_id,
            "OobNotifierAdapter::await_resolution called on dispatcher; \
             use a channel directly or MockOobNotifier in tests",
        );
        Err(OobError::Unavailable)
    }

    async fn available(&self) -> bool {
        // Adapter is available when at least one channel is available.
        self.desktop.available().await
            || self.terminal.available().await
            || self.localhost.available().await
    }
}
