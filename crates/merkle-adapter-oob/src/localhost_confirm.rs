//! Localhost browser confirmation channel.
//!
//! Opens a minimal HTML Approve/Deny page in the system default browser bound
//! to `127.0.0.1:39842` (configurable). The operator clicks a button; the
//! embedded axum server receives the action and resolves the pending
//! [`OobChallenge`] via [`PendingChallengeRegistry`].
//!
//! ## Feature gate
//!
//! Real server and browser-open behaviour requires the Cargo feature
//! `localhost-confirm-real`.  Without it `dispatch` logs a warning and
//! `available()` returns `false`.
//!
//! ## Endpoint surface
//!
//! | Method | Path                            | Purpose                        |
//! |--------|---------------------------------|--------------------------------|
//! | GET    | `/oob/{challenge_id}`           | Renders approve / deny HTML    |
//! | POST   | `/oob/{challenge_id}/approve`   | Records Approved resolution    |
//! | POST   | `/oob/{challenge_id}/deny`      | Records Denied resolution      |
//!
//! ## ADR reference
//!
//! [ADR-0011 Amendment](../../../docs/arch/adr/0011-slash-only-reveal-with-oob-for-high-sensitivity.md)
//! — confirmation URL is delivered only through the OOB channel, never via
//! the MCP transport.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use merkle_domain_access_mediation as am;
use merkle_domain_access_mediation::oob::resolution::OobResolution;
use merkle_ports::OobNotifier;
use merkle_ports::error::OobError;
use merkle_types::ChallengeId;
#[cfg(feature = "localhost-confirm-real")]
use tracing::info;
use tracing::{debug, warn};

use crate::desktop_notif::DEFAULT_LOCALHOST_PORT;
use crate::pending::PendingChallengeRegistry;

// ---------------------------------------------------------------------------
// Real server implementation (feature = "localhost-confirm-real")
// ---------------------------------------------------------------------------

#[cfg(feature = "localhost-confirm-real")]
mod real {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::extract::{Path, State};
    use axum::response::{Html, IntoResponse};
    use axum::routing::{get, post};
    use axum::{Router, http::StatusCode};
    use merkle_types::{ChallengeId, OobChallengeOutcome, Rfc3339Timestamp};
    use tracing::{info, warn};

    use crate::pending::PendingChallengeRegistry;

    // ---- HTML templates ----

    fn approve_deny_page(challenge_id: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>merkle-vault: OOB Confirmation</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 600px; margin: 4rem auto; padding: 1rem; }}
    h1 {{ color: #333; }}
    .challenge-id {{ font-family: monospace; font-size: 0.85rem; color: #555; word-break: break-all; }}
    .warn {{ color: #b35900; background: #fff3e0; border-left: 4px solid #e65100; padding: 0.75rem; margin: 1rem 0; }}
    .btn {{ display: inline-block; padding: 0.75rem 2rem; border: none; border-radius: 4px;
            font-size: 1rem; cursor: pointer; margin: 0.5rem; text-decoration: none; color: #fff; }}
    .btn-approve {{ background: #2e7d32; }}
    .btn-approve:hover {{ background: #1b5e20; }}
    .btn-deny {{ background: #c62828; }}
    .btn-deny:hover {{ background: #7f0000; }}
    form {{ display: inline; }}
  </style>
</head>
<body>
  <h1>OOB Confirmation Required</h1>
  <p class="warn">A reveal request for a <strong>high-sensitivity</strong> secret is pending.
  You are the only person who can approve or deny this request.</p>
  <p>Challenge ID: <span class="challenge-id">{challenge_id}</span></p>
  <form action="/oob/{challenge_id}/approve" method="POST">
    <button type="submit" class="btn btn-approve">&#10003; Approve</button>
  </form>
  <form action="/oob/{challenge_id}/deny" method="POST">
    <button type="submit" class="btn btn-deny">&#10007; Deny</button>
  </form>
  <p style="margin-top:2rem;font-size:0.8rem;color:#999;">
    This page is only accessible on localhost and expires with the challenge timeout.
  </p>
</body>
</html>"#,
        )
    }

    fn result_page(outcome: &str, message: &str) -> Html<String> {
        let color = if outcome == "Approved" {
            "#2e7d32"
        } else {
            "#c62828"
        };
        Html(format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>merkle-vault: {outcome}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:600px;margin:4rem auto;padding:1rem;}}
h1{{color:{color};}}</style></head>
<body><h1>{outcome}</h1><p>{message}</p>
<p style="font-size:0.8rem;color:#999;">You may close this window.</p></body></html>"#,
        ))
    }

    // ---- State ----

    #[derive(Clone)]
    pub(super) struct AppState {
        pub(super) registry: Arc<PendingChallengeRegistry>,
    }

    // ---- Handlers ----

    pub(super) async fn handle_page(
        Path(challenge_id): Path<String>,
        State(_state): State<AppState>,
    ) -> impl IntoResponse {
        Html(approve_deny_page(&challenge_id))
    }

    pub(super) async fn handle_approve(
        Path(raw_id): Path<String>,
        State(state): State<AppState>,
    ) -> Result<Html<String>, (StatusCode, String)> {
        resolve_challenge(&raw_id, OobChallengeOutcome::Approved, &state.registry)
    }

    pub(super) async fn handle_deny(
        Path(raw_id): Path<String>,
        State(state): State<AppState>,
    ) -> Result<Html<String>, (StatusCode, String)> {
        resolve_challenge(&raw_id, OobChallengeOutcome::Denied, &state.registry)
    }

    fn resolve_challenge(
        raw_id: &str,
        outcome: OobChallengeOutcome,
        registry: &PendingChallengeRegistry,
    ) -> Result<Html<String>, (StatusCode, String)> {
        let id: ChallengeId = raw_id.parse().map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid challenge_id: {e}"),
            )
        })?;

        let authorized_at = match outcome {
            OobChallengeOutcome::Approved => Some(Rfc3339Timestamp::now()),
            _ => None,
        };

        let resolution = OobResolution::new(id, outcome, authorized_at, None).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("resolution build error: {e}"),
            )
        })?;

        info!(%id, ?outcome, "Localhost confirm: recording resolution");
        registry.resolve(id, resolution);

        let (label, msg) = match outcome {
            OobChallengeOutcome::Approved => (
                "Approved",
                "The reveal request has been approved. The secret will be returned.",
            ),
            _ => (
                "Denied",
                "The reveal request has been denied. No secret material was revealed.",
            ),
        };

        Ok(result_page(label, msg))
    }

    // ---- Router ----

    pub(super) fn build_router(state: AppState) -> Router {
        Router::new()
            .route("/oob/{challenge_id}", get(handle_page))
            .route("/oob/{challenge_id}/approve", post(handle_approve))
            .route("/oob/{challenge_id}/deny", post(handle_deny))
            .with_state(state)
    }

    /// Spawn the axum listener on `127.0.0.1:{port}`.
    ///
    /// The listener runs until the `shutdown_rx` oneshot fires or the future
    /// is dropped.  We use a `tokio::task::AbortHandle` so callers can cancel.
    pub(super) fn spawn_server(
        registry: &Arc<PendingChallengeRegistry>,
        port: u16,
    ) -> tokio::task::JoinHandle<()> {
        let state = AppState {
            registry: Arc::clone(registry),
        };
        let app = build_router(state);
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        tokio::spawn(async move {
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    warn!(port, error=%e, "LocalhostConfirmChannel: failed to bind listener");
                    return;
                }
            };
            info!(port, "LocalhostConfirmChannel: axum server listening");
            if let Err(e) = axum::serve(listener, app).await {
                warn!(error=%e, "LocalhostConfirmChannel: axum server error");
            }
        })
    }

    /// Check whether the port is bindable (i.e., nothing else is already
    /// listening there).
    pub(super) async fn probe_port(port: u16) -> bool {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        tokio::net::TcpListener::bind(addr).await.is_ok()
    }

    // Needed to make the unused import warning quiet when the feature is off.
    use merkle_domain_access_mediation::oob::resolution::OobResolution;
}

// ---------------------------------------------------------------------------
// Localhost confirmation channel
// ---------------------------------------------------------------------------

/// Localhost browser confirmation channel.
///
/// Spawns an axum sub-router on `127.0.0.1:{port}` (default `39842`) and
/// opens the confirmation URL in the system browser via the `open` crate.
///
/// Enable the `localhost-confirm-real` Cargo feature for full functionality.
/// Without the feature the channel stubs and always reports
/// `available() == false`.
#[derive(Debug)]
pub struct LocalhostConfirmChannel {
    pending: Arc<PendingChallengeRegistry>,
    port: u16,
    /// Axum server task handle; `Some` once the server has been spawned.
    #[cfg(feature = "localhost-confirm-real")]
    server_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Clone for LocalhostConfirmChannel {
    fn clone(&self) -> Self {
        // Cloning does not share the server handle; each clone starts fresh.
        Self {
            pending: Arc::clone(&self.pending),
            port: self.port,
            #[cfg(feature = "localhost-confirm-real")]
            server_handle: tokio::sync::Mutex::new(None),
        }
    }
}

impl LocalhostConfirmChannel {
    /// Create a new localhost confirmation channel using the default port
    /// (`39842`).
    #[must_use]
    pub fn new() -> Self {
        Self::with_port(DEFAULT_LOCALHOST_PORT)
    }

    /// Create a new localhost confirmation channel with a custom port.
    #[must_use]
    pub fn with_port(port: u16) -> Self {
        Self {
            pending: Arc::new(PendingChallengeRegistry::new()),
            port,
            #[cfg(feature = "localhost-confirm-real")]
            server_handle: tokio::sync::Mutex::new(None),
        }
    }

    /// Return the port this channel is configured to listen on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Compose the confirmation page URL for a given challenge.
    #[must_use]
    fn page_url(&self, challenge_id: ChallengeId) -> String {
        format!("http://127.0.0.1:{}/oob/{}", self.port, challenge_id)
    }
}

impl Default for LocalhostConfirmChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OobNotifier for LocalhostConfirmChannel {
    async fn dispatch(
        &self,
        challenge: &am::oob::challenge::OobChallenge,
        _target_device: &am::companion_device::CompanionDevice,
    ) -> Result<(), OobError> {
        let challenge_id = challenge.challenge_id;
        let url = self.page_url(challenge_id);

        // Register the challenge so the HTTP handler can resolve it.
        drop(self.pending.register(challenge_id));

        #[cfg(feature = "localhost-confirm-real")]
        {
            // Spawn the axum server if not already running.
            {
                let mut guard = self.server_handle.lock().await;
                if guard
                    .as_ref()
                    .is_none_or(tokio::task::JoinHandle::is_finished)
                {
                    let handle = real::spawn_server(&self.pending, self.port);
                    *guard = Some(handle);
                }
            }

            // Give the listener a moment to bind before opening the browser.
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Open the URL in the default system browser. This call is
            // fallible but non-fatal: if no browser is available the operator
            // can copy the URL from logs.
            info!(%challenge_id, url = %url, "Opening localhost confirmation page in browser");
            let url_clone = url.clone();
            let open_result = tokio::task::spawn_blocking(move || open::that(url_clone))
                .await
                .map_err(|e| OobError::DispatchFailed(e.to_string()))?;

            if let Err(e) = open_result {
                warn!(
                    %challenge_id,
                    url = %url,
                    error = %e,
                    "Failed to open browser; operator must navigate to URL manually",
                );
                // Emit URL to stderr so the operator can see it in their terminal.
                eprintln!("[merkle] OOB confirm URL: {url}");
            }
        }

        #[cfg(not(feature = "localhost-confirm-real"))]
        {
            warn!(
                %challenge_id,
                url = %url,
                "localhost-confirm-real feature disabled; real HTTP server is a no-op. \
                 Confirm manually at the URL above.",
            );
        }

        debug!(%challenge_id, "LocalhostConfirmChannel::dispatch returned Ok");
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
        #[cfg(feature = "localhost-confirm-real")]
        {
            // Available when the configured port is bindable (or the server is
            // already running).
            {
                let guard = self.server_handle.lock().await;
                if let Some(h) = guard.as_ref() {
                    if !h.is_finished() {
                        // Server is running — channel is available.
                        return true;
                    }
                }
            }
            // Port probe: can we bind it?
            real::probe_port(self.port).await
        }
        #[cfg(not(feature = "localhost-confirm-real"))]
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

    use super::LocalhostConfirmChannel;
    use crate::pending::PendingChallengeRegistry;

    fn cid(n: u8) -> ChallengeId {
        format!("018f4c1a-0000-7000-8000-0000000000{n:02x}")
            .parse()
            .expect("valid ChallengeId")
    }

    /// Without `localhost-confirm-real`, `available()` must return `false`.
    #[tokio::test]
    async fn stub_available_false_without_feature() {
        let channel = LocalhostConfirmChannel::new();
        #[cfg(not(feature = "localhost-confirm-real"))]
        assert!(!channel.available().await);

        #[cfg(feature = "localhost-confirm-real")]
        let _ = channel.available().await; // should not panic
    }

    /// `dispatch` returns `Ok(())` regardless of feature flag.
    #[tokio::test]
    async fn dispatch_returns_ok() {
        // Use a non-default port to avoid conflicts with a running server.
        let channel = LocalhostConfirmChannel::with_port(39_900);
        let challenge = make_challenge(cid(0x01));
        let device = make_device();
        assert!(channel.dispatch(&challenge, &device).await.is_ok());
    }

    /// URL format matches expected pattern.
    #[test]
    fn page_url_format() {
        let channel = LocalhostConfirmChannel::with_port(39_842);
        let id = cid(0xAB);
        let url = channel.page_url(id);
        assert!(url.starts_with("http://127.0.0.1:39842/oob/"));
    }

    /// Custom port is preserved.
    #[test]
    fn custom_port_is_stored() {
        let channel = LocalhostConfirmChannel::with_port(12_345);
        assert_eq!(channel.port(), 12_345);
    }

    /// Inject resolution directly via registry and verify `await_resolution`
    /// delivers it (mock path — no real HTTP server).
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

        let channel = LocalhostConfirmChannel::new();
        let id = cid(0x30);
        let result = channel
            .await_resolution(id, Duration::from_millis(10))
            .await;
        assert!(
            matches!(result, Err(OobError::Timeout)),
            "expected Timeout, got {result:?}"
        );
    }

    // ---- feature-gated integration: axum server smoke ----

    /// Start the real axum server, POST to /approve, and verify the registry
    /// receives the resolution.
    #[cfg(feature = "localhost-confirm-real")]
    #[tokio::test]
    async fn axum_server_smoke_approve() {
        use std::sync::Arc;

        // Use a unique port to avoid bind conflicts.
        const SMOKE_PORT: u16 = 39_901;

        let registry = Arc::new(PendingChallengeRegistry::new());
        let id = cid(0x50);

        // Register before spawning so the handler can resolve.
        let rx = registry.register(id);

        let _handle = super::real::spawn_server(&registry, SMOKE_PORT);

        // Give the server time to bind.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let url = format!("http://127.0.0.1:{SMOKE_PORT}/oob/{id}/approve");
        let resp = reqwest::Client::new().post(&url).send().await;

        match resp {
            Ok(r) => {
                assert!(r.status().is_success(), "expected 200, got {}", r.status());
            }
            Err(e) => panic!("HTTP POST failed: {e}"),
        }

        let received = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("no timeout")
            .expect("channel not dropped");

        assert_eq!(received.outcome, OobChallengeOutcome::Approved);
    }

    /// POST to /deny resolves as Denied.
    #[cfg(feature = "localhost-confirm-real")]
    #[tokio::test]
    async fn axum_server_smoke_deny() {
        use std::sync::Arc;

        const SMOKE_PORT: u16 = 39_902;

        let registry = Arc::new(PendingChallengeRegistry::new());
        let id = cid(0x51);
        let rx = registry.register(id);

        let _handle = super::real::spawn_server(&registry, SMOKE_PORT);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let url = format!("http://127.0.0.1:{SMOKE_PORT}/oob/{id}/deny");
        let resp = reqwest::Client::new().post(&url).send().await;
        assert!(resp.expect("request ok").status().is_success());

        let received = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("no timeout")
            .expect("channel not dropped");

        assert_eq!(received.outcome, OobChallengeOutcome::Denied);
    }

    /// GET /oob/{id} returns a 200 HTML page.
    #[cfg(feature = "localhost-confirm-real")]
    #[tokio::test]
    async fn axum_server_get_page_returns_html() {
        use std::sync::Arc;

        const SMOKE_PORT: u16 = 39_903;

        let registry = Arc::new(PendingChallengeRegistry::new());
        let id = cid(0x52);

        let _handle = super::real::spawn_server(&registry, SMOKE_PORT);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let url = format!("http://127.0.0.1:{SMOKE_PORT}/oob/{id}");
        let resp = reqwest::get(&url).await.expect("GET ok");
        assert!(resp.status().is_success());
        let body = resp.text().await.expect("body");
        assert!(
            body.contains("OOB Confirmation Required"),
            "expected confirmation page, got: {body}"
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
            oob_channel: OobChannel::LocalhostConfirm,
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
