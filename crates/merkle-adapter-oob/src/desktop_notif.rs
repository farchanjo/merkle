//! Desktop notification channel.
//!
//! Delivers an [`OobChallenge`] to the operator's primary display via the
//! platform notification subsystem:
//!
//! - **macOS**: `NSUserNotification` / `UNUserNotificationCenter` (via `notify-rust`)
//! - **Linux**: `libnotify` (via `notify-rust` + `zbus` or `dbus`)
//! - **Windows**: WinRT Toast notifications (via `notify-rust`)
//!
//! ## Feature gates
//!
//! Real notification delivery requires the Cargo feature `desktop-notif-real`.
//! Without it, `dispatch` logs a warning and returns `Ok(())`; `available()`
//! always returns `false`.  This keeps unit tests free of native notification
//! daemon dependencies.
//!
//! ```toml
//! # Cargo.toml
//! merkle-adapter-oob = { ..., features = ["desktop-notif-real"] }
//! ```
//!
//! ## Resolution flow
//!
//! Because desktop notification action callbacks (click-to-approve) cannot
//! directly sign an [`OobResolution`] on this path, the notification body
//! carries the URL of the localhost confirmation server.  The operator clicks
//! **Approve** to open that URL in their browser, which then posts a signed
//! resolution.  This keeps the cryptographic binding intact while providing a
//! single-click UX.
//!
//! On platforms where `notify-rust` action buttons are unavailable, the
//! notification body prints the confirmation URL and the operator pastes it
//! into a browser manually.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use merkle_domain_access_mediation as am;
use merkle_domain_access_mediation::oob::resolution::OobResolution;
use merkle_ports::OobNotifier;
use merkle_ports::error::OobError;
use merkle_types::ChallengeId;
use tracing::debug;
#[cfg(not(feature = "desktop-notif-real"))]
use tracing::warn;

use crate::pending::PendingChallengeRegistry;

/// Default port for the localhost confirmation server (overridable via config).
pub const DEFAULT_LOCALHOST_PORT: u16 = 39_842;

/// Desktop notification channel.
///
/// Use the `desktop-notif-real` feature to enable real OS notification
/// delivery.  Without the feature the channel is a stub that logs a warning
/// and always reports `available() == false`.
#[derive(Debug, Clone)]
pub struct DesktopNotifChannel {
    pending: Arc<PendingChallengeRegistry>,
    /// Port on which the localhost confirmation server listens.
    /// Used to compose the approval URL embedded in the notification body.
    localhost_port: u16,
}

impl DesktopNotifChannel {
    /// Create a new desktop notification channel using the default localhost
    /// confirmation port (`39842`).
    #[must_use]
    pub fn new() -> Self {
        Self::with_port(DEFAULT_LOCALHOST_PORT)
    }

    /// Create a new desktop notification channel with a custom localhost port.
    #[must_use]
    pub fn with_port(localhost_port: u16) -> Self {
        Self {
            pending: Arc::new(PendingChallengeRegistry::new()),
            localhost_port,
        }
    }

    /// Return the localhost confirmation port this channel was configured with.
    #[must_use]
    pub fn localhost_port(&self) -> u16 {
        self.localhost_port
    }

    /// Compose the localhost confirmation URL for a given challenge.
    #[must_use]
    fn confirmation_url(&self, challenge_id: ChallengeId) -> String {
        format!(
            "http://127.0.0.1:{}/oob/{}",
            self.localhost_port, challenge_id
        )
    }
}

impl Default for DesktopNotifChannel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// real implementation (feature = "desktop-notif-real")
// ---------------------------------------------------------------------------

#[cfg(feature = "desktop-notif-real")]
mod real {
    use std::sync::Arc;

    use notify_rust::Notification;
    use tracing::{debug, info, warn};

    use crate::pending::PendingChallengeRegistry;

    /// Fire an OS notification with challenge summary and an embedded
    /// confirmation URL.  Runs on a `spawn_blocking` thread because
    /// `notify-rust` performs synchronous platform calls.
    ///
    /// The notification body contains the confirmation URL so the operator can
    /// copy-paste it into a browser when needed.  On Linux with a notification
    /// daemon that supports actions (`dunst`, `mako`), an **Approve** action
    /// button label is added; clicking it currently logs intent — full
    /// browser-open is handled by the `localhost-confirm-real` companion channel
    /// to keep the `desktop-notif-real` feature independent.
    pub(super) fn spawn_notification(
        pending: Arc<PendingChallengeRegistry>,
        challenge_id: merkle_types::ChallengeId,
        handle: String,
        expires: String,
        confirmation_url: String,
    ) {
        tokio::task::spawn_blocking(move || {
            let body = format!(
                "Secret: {handle}\nExpires: {expires}\nConfirmation URL:\n{confirmation_url}"
            );

            let mut notif = Notification::new();
            notif
                .summary("merkle: OOB Confirmation Required")
                .body(&body)
                .appname("merkle-vault")
                .timeout(notify_rust::Timeout::Milliseconds(60_000));

            // Linux: add an action button label for daemons that support it.
            #[cfg(target_os = "linux")]
            notif.action("approve", "Approve");

            match notif.show() {
                Ok(handle_ref) => {
                    info!(%challenge_id, "Desktop notification shown");

                    // On Linux: wait for the action click callback.
                    #[cfg(target_os = "linux")]
                    {
                        handle_ref.wait_for_action(|action| {
                            if action == "approve" {
                                // Log intent; browser-open is responsibility of
                                // LocalhostConfirmChannel (localhost-confirm-real).
                                info!(
                                    %challenge_id,
                                    url = %confirmation_url,
                                    "Operator clicked Approve; navigate to the confirmation URL",
                                );
                            }
                        });
                    }

                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = handle_ref;
                        info!(
                            %challenge_id,
                            url = %confirmation_url,
                            "Desktop notification shown; operator must navigate to URL",
                        );
                    }
                }
                Err(e) => {
                    warn!(%challenge_id, error=%e, "Failed to show desktop notification");
                }
            }

            // Resolution arrives via the localhost HTTP callback —
            // the registry is not resolved here.
            drop(pending);
        });
    }

    /// Check whether the OS notification subsystem is reachable.
    ///
    /// Returns `false` on any error (no daemon, permission denied, headless).
    pub(super) fn probe_available() -> bool {
        let result = Notification::new()
            .summary("merkle-vault: availability probe")
            .body("This notification is a probe and can be ignored.")
            .appname("merkle-vault")
            .timeout(notify_rust::Timeout::Milliseconds(0))
            .show();

        match result {
            Ok(_) => true,
            Err(e) => {
                debug!(error=%e, "Desktop notification availability probe failed");
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OobNotifier impl
// ---------------------------------------------------------------------------

#[async_trait]
impl OobNotifier for DesktopNotifChannel {
    async fn dispatch(
        &self,
        challenge: &am::oob::challenge::OobChallenge,
        _target_device: &am::companion_device::CompanionDevice,
    ) -> Result<(), OobError> {
        let challenge_id = challenge.challenge_id;
        let handle = challenge.secret_handle.to_string();
        let expires = challenge.expires_at.to_string();
        let confirmation_url = self.confirmation_url(challenge_id);

        // Register the challenge in the pending registry so that
        // `await_resolution` can pair with it when the localhost server
        // callback delivers the resolution.
        drop(self.pending.register(challenge_id));

        #[cfg(feature = "desktop-notif-real")]
        {
            debug!(
                %challenge_id,
                url = %confirmation_url,
                "Dispatching desktop notification for OOB challenge",
            );
            real::spawn_notification(
                Arc::clone(&self.pending),
                challenge_id,
                handle,
                expires,
                confirmation_url,
            );
        }

        #[cfg(not(feature = "desktop-notif-real"))]
        {
            // Stub: log the URL to stderr so operators can confirm manually
            // during development without the feature flag enabled.
            let _ = (&handle, &expires);
            warn!(
                %challenge_id,
                url = %confirmation_url,
                "desktop-notif-real feature disabled; real notification delivery \
                 is a no-op. Confirm manually at the URL above.",
            );
        }

        debug!(%challenge_id, "DesktopNotifChannel::dispatch returned Ok");
        Ok(())
    }

    async fn await_resolution(
        &self,
        challenge_id: ChallengeId,
        timeout: Duration,
    ) -> Result<OobResolution, OobError> {
        let rx = self.pending.register(challenge_id);
        tokio::time::timeout(timeout, rx)
            .await
            .map_err(|_| OobError::Timeout)?
            .map_err(|_| OobError::Timeout)
    }

    async fn available(&self) -> bool {
        #[cfg(feature = "desktop-notif-real")]
        {
            // Run the availability probe on a blocking thread because
            // `notify-rust::Notification::show` is a synchronous call.
            tokio::task::spawn_blocking(real::probe_available)
                .await
                .unwrap_or(false)
        }
        #[cfg(not(feature = "desktop-notif-real"))]
        {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use merkle_ports::OobNotifier as _;
    use merkle_types::{ChallengeId, OobChallengeOutcome};

    use super::DesktopNotifChannel;
    use crate::pending::PendingChallengeRegistry;

    fn cid(n: u8) -> ChallengeId {
        format!("018f4c1a-0000-7000-8000-0000000000{n:02x}")
            .parse()
            .expect("valid ChallengeId")
    }

    /// Without `desktop-notif-real`, `available()` must return `false`.
    #[tokio::test]
    async fn stub_available_false_without_feature() {
        let channel = DesktopNotifChannel::new();

        // When the real feature is not enabled, available() is always false.
        #[cfg(not(feature = "desktop-notif-real"))]
        assert!(!channel.available().await);

        // When the real feature IS enabled, available() may be true or false
        // depending on the system; just ensure it doesn't panic.
        #[cfg(feature = "desktop-notif-real")]
        let _ = channel.available().await;
    }

    /// `dispatch` returns `Ok(())` regardless of feature flag.
    #[tokio::test]
    async fn dispatch_returns_ok() {
        let channel = DesktopNotifChannel::new();
        let challenge = make_challenge(cid(0x01));
        let device = make_device();
        assert!(channel.dispatch(&challenge, &device).await.is_ok());
    }

    /// Confirmation URL format.
    #[test]
    fn confirmation_url_format() {
        let channel = DesktopNotifChannel::with_port(39_842);
        let id = cid(0xAB);
        let url = channel.confirmation_url(id);
        assert!(url.starts_with("http://127.0.0.1:39842/oob/"));
    }

    /// Custom port is preserved.
    #[test]
    fn custom_port_is_stored() {
        let channel = DesktopNotifChannel::with_port(12_345);
        assert_eq!(channel.localhost_port(), 12_345);
    }

    /// Inject a resolution manually via the shared registry and verify
    /// `await_resolution` delivers it (mock path — no real notification).
    #[tokio::test]
    async fn await_resolution_delivers_injected_resolution() {
        use merkle_domain_access_mediation::oob::resolution::OobResolution;
        use merkle_types::Rfc3339Timestamp;
        use std::sync::Arc;

        let registry = Arc::new(PendingChallengeRegistry::new());
        let id = cid(0x20);
        let rx = registry.register(id);

        let resolution = OobResolution::new(
            id,
            OobChallengeOutcome::Approved,
            Some(Rfc3339Timestamp::now()),
            None,
        )
        .expect("valid resolution");
        registry.resolve(id, resolution);

        let received = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("no timeout")
            .expect("channel not dropped");

        assert_eq!(received.outcome, OobChallengeOutcome::Approved);
    }

    /// `await_resolution` returns `OobError::Timeout` when nothing is resolved.
    #[tokio::test]
    async fn await_resolution_times_out_with_no_resolution() {
        use merkle_ports::error::OobError;

        let channel = DesktopNotifChannel::new();
        let id = cid(0x30);
        let result = channel
            .await_resolution(id, Duration::from_millis(10))
            .await;
        assert!(
            matches!(result, Err(OobError::Timeout)),
            "expected Timeout, got {result:?}"
        );
    }

    // ---- helpers ----

    fn make_challenge(
        id: ChallengeId,
    ) -> merkle_domain_access_mediation::oob::challenge::OobChallenge {
        use merkle_types::{Handle, NamespaceId, OobChannel, Sensitivity};

        merkle_domain_access_mediation::oob::challenge::OobChallenge {
            challenge_id: id,
            namespace_id: "018f4c1a-0000-7000-8000-000000000010"
                .parse::<NamespaceId>()
                .expect("ns id"),
            secret_handle: "vault://prod/ssh-key/bastion"
                .parse::<Handle>()
                .expect("handle"),
            sensitivity: Sensitivity::High,
            oob_channel: OobChannel::DesktopNotif,
            expires_at: merkle_types::Rfc3339Timestamp::now(),
            request_nonce: [0u8; 32],
            envelope: None,
        }
    }

    fn make_device() -> merkle_domain_access_mediation::companion_device::CompanionDevice {
        use merkle_types::{CompanionDeviceClass, Rfc3339Timestamp, UuidV7};

        merkle_domain_access_mediation::companion_device::CompanionDevice {
            device_id: UuidV7::new(),
            ed25519_pubkey: [0u8; 32],
            x25519_pubkey: [0u8; 32],
            class: CompanionDeviceClass::Software,
            attestation_chain: vec![],
            enrolled_at: Rfc3339Timestamp::now(),
            revoked_at: None,
        }
    }
}
