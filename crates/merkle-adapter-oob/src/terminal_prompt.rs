//! Terminal TTY prompt channel — polished implementation.
//!
//! Writes challenge details to the agent's controlling TTY (via
//! `/dev/tty` on Unix) and waits for the operator to press `y` (approve)
//! or `n` (deny).
//!
//! ## Headless / CI behaviour
//!
//! When the environment variable `MERKLE_OOB_AUTO_DENY=1` is set, `dispatch`
//! immediately records a [`OobChallengeOutcome::Denied`] resolution without
//! reading from the TTY.  This is intended for automated test pipelines where
//! no controlling terminal is available.  **Production deployments MUST NOT
//! set this variable.**
//!
//! ## Timeout handling
//!
//! If the operator does not respond before `expires_at`, the pending entry is
//! resolved with [`OobChallengeOutcome::Expired`].  `await_resolution` will
//! return [`OobError::Timeout`] in that case.
//!
//! ## Signature note
//!
//! Because the resolution is produced by the Vault Agent process itself
//! (reading a TTY key press), there is no Companion Device to provide an
//! Ed25519 signature.  The returned [`OobResolution`] carries
//! `device_signature: None` and reflects whatever the operator typed.

use std::collections::HashMap;
use std::io::{self, Write as _};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use merkle_domain_access_mediation as am;
use merkle_domain_access_mediation::oob::resolution::OobResolution;
use merkle_ports::error::OobError;
use merkle_ports::OobNotifier;
use merkle_types::{ChallengeId, OobChallengeOutcome, Rfc3339Timestamp};
use parking_lot::Mutex;
use tracing::{debug, warn};

use crate::pending::PendingChallengeRegistry;

// ---------------------------------------------------------------------------
// ANSI helpers (no external crate dependency)
// ---------------------------------------------------------------------------

/// Bold + bright green.
const ANSI_GREEN_BOLD: &str = "\x1b[1;32m";
/// Bold + bright yellow.
const ANSI_YELLOW_BOLD: &str = "\x1b[1;33m";
/// Bold + bright red.
const ANSI_RED_BOLD: &str = "\x1b[1;31m";
/// Reset all attributes.
const ANSI_RESET: &str = "\x1b[0m";

/// Terminal TTY prompt channel.
///
/// Prompts the operator on `/dev/tty` (stderr fallback on non-Unix) and
/// waits for a `y`/`n` keystroke.  The key-read runs on a
/// `spawn_blocking` thread so the Tokio executor is never blocked.
///
/// See module-level documentation for headless, timeout, and ANSI details.
#[derive(Debug, Clone)]
pub struct TerminalPromptChannel {
    // Arc so the registry can be shared with the blocking task without
    // borrowing `self` (which would not satisfy `'static` in tokio::spawn).
    pending: Arc<PendingChallengeRegistry>,
    /// Pre-resolved resolutions from the auto-deny fast-path.
    ///
    /// When `dispatch` resolves synchronously (auto-deny), the resolution is
    /// stored here keyed by `ChallengeId`.  `await_resolution` checks this
    /// map first before waiting on the registry channel — this avoids a
    /// race where `resolve()` fires before `register()` is called.
    pre_resolved: Arc<Mutex<HashMap<ChallengeId, OobResolution>>>,
    /// When `true`, bypass env-var check and always auto-deny.
    /// Used in unit tests to avoid `unsafe { set_var(...) }`.
    #[cfg(test)]
    force_auto_deny: bool,
}

impl TerminalPromptChannel {
    /// Create a new terminal prompt channel.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: Arc::new(PendingChallengeRegistry::new()),
            pre_resolved: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            force_auto_deny: false,
        }
    }

    /// Create a channel that unconditionally auto-denies without reading the TTY.
    ///
    /// For unit tests only — avoids the need for `unsafe { std::env::set_var(...) }`.
    #[cfg(test)]
    #[must_use]
    pub fn new_auto_deny_for_test() -> Self {
        Self {
            pending: Arc::new(PendingChallengeRegistry::new()),
            pre_resolved: Arc::new(Mutex::new(HashMap::new())),
            force_auto_deny: true,
        }
    }

    /// Returns `true` if the auto-deny fast-path should be taken.
    ///
    /// In non-test builds `self` is not needed (the env-var path is stateless);
    /// under `#[cfg(test)]` it reads `self.force_auto_deny`.
    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "self.force_auto_deny is read under #[cfg(test)]; unused in release builds by design"
        )
    )]
    fn is_auto_deny(&self) -> bool {
        #[cfg(test)]
        if self.force_auto_deny {
            return true;
        }
        std::env::var("MERKLE_OOB_AUTO_DENY").as_deref() == Ok("1")
    }
}

impl Default for TerminalPromptChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OobNotifier for TerminalPromptChannel {
    async fn dispatch(
        &self,
        challenge: &am::oob::challenge::OobChallenge,
        _target_device: &am::companion_device::CompanionDevice,
    ) -> Result<(), OobError> {
        // ChallengeId is Copy — no .clone() needed.
        let challenge_id = challenge.challenge_id;
        let handle = challenge.secret_handle.to_string();
        let channel = challenge.oob_channel.to_string();
        let expires = challenge.expires_at.to_string();
        let expires_at = challenge.expires_at;

        // Clone the Arc — cheap, gives the spawned task 'static access.
        let pending = Arc::clone(&self.pending);

        // --- Headless / CI fast-path: MERKLE_OOB_AUTO_DENY=1 (or test override) ---
        if self.is_auto_deny() {
            warn!(
                %challenge_id,
                "MERKLE_OOB_AUTO_DENY=1: recording Denied resolution immediately (headless mode)",
            );
            let resolution =
                OobResolution::new(challenge_id, OobChallengeOutcome::Denied, None, None)
                    .map_err(|e| OobError::DispatchFailed(e.to_string()))?;
            // Store in `pre_resolved` so `await_resolution` can pick it up even
            // if it is called after this synchronous resolution.
            self.pre_resolved.lock().insert(challenge_id, resolution);
            return Ok(());
        }

        // One-shot channel: blocking task → async forwarder.
        let (tty_tx, tty_rx) = tokio::sync::oneshot::channel::<OobResolution>();

        // Run the blocking TTY I/O on a Tokio blocking thread.
        tokio::task::spawn_blocking(move || {
            let mut tty = open_tty_write();
            let _ = writeln!(
                tty,
                "\n{ANSI_YELLOW_BOLD}[merkle] OOB Confirmation required{ANSI_RESET}\
                 \n  Handle:  {handle}\
                 \n  Channel: {channel}\
                 \n  Expires: {expires}\
                 \n  Challenge: {challenge_id}\
                 \n{ANSI_GREEN_BOLD}Approve?{ANSI_RESET} \
                 {ANSI_GREEN_BOLD}[y]{ANSI_RESET}/{ANSI_RED_BOLD}[N]{ANSI_RESET}: ",
            );
            let _ = tty.flush();

            let key = read_key_from_tty();
            debug!(%key, "TTY operator input received");

            let resolution = match key {
                'y' | 'Y' => OobResolution::new(
                    challenge_id,
                    OobChallengeOutcome::Approved,
                    Some(Rfc3339Timestamp::now()),
                    // No Companion Device signature on the TTY path.
                    None,
                ),
                _ => OobResolution::new(challenge_id, OobChallengeOutcome::Denied, None, None),
            };

            match resolution {
                Ok(res) => {
                    // Ignore error: receiver may have been dropped on timeout.
                    let _ = tty_tx.send(res);
                }
                Err(e) => {
                    warn!("Failed to build OobResolution from TTY input: {e}");
                }
            }
        });

        // Compute the duration until `expires_at` (at least 1 ms).
        let deadline_duration = {
            let now = Rfc3339Timestamp::now();
            let delta_ms = (expires_at.inner() - now.inner()).num_milliseconds();
            if delta_ms > 0 {
                // delta_ms > 0 is checked by the if-guard; value is non-negative.
                #[expect(
                    clippy::cast_sign_loss,
                    reason = "delta_ms > 0 asserted by the branch guard; cast is lossless"
                )]
                Duration::from_millis(delta_ms as u64)
            } else {
                Duration::from_millis(1)
            }
        };

        // Forward the blocking task's result into the shared registry so
        // that `await_resolution` can pick it up. If the operator does not
        // respond before `expires_at`, record Expired.
        let pending2 = Arc::clone(&self.pending);
        tokio::spawn(async move {
            match tokio::time::timeout(deadline_duration, tty_rx).await {
                Ok(Ok(res)) => {
                    pending.resolve(challenge_id, res);
                }
                Ok(Err(_)) => {
                    // Sender dropped (blocking task panicked) — treat as Denied.
                    warn!(%challenge_id, "TTY blocking task sender dropped; recording Denied");
                    if let Ok(res) =
                        OobResolution::new(challenge_id, OobChallengeOutcome::Denied, None, None)
                    {
                        pending.resolve(challenge_id, res);
                    }
                }
                Err(_) => {
                    // Timeout from expires_at — resolve as Expired.
                    warn!(%challenge_id, "TTY response deadline reached; recording Expired");
                    if let Ok(res) =
                        OobResolution::new(challenge_id, OobChallengeOutcome::Expired, None, None)
                    {
                        pending2.resolve(challenge_id, res);
                    }
                }
            }
        });

        Ok(())
    }

    async fn await_resolution(
        &self,
        challenge_id: ChallengeId,
        timeout: Duration,
    ) -> Result<OobResolution, OobError> {
        // Fast path: auto-deny resolutions are stored synchronously in
        // `pre_resolved` before `await_resolution` is called.
        if let Some(res) = self.pre_resolved.lock().remove(&challenge_id) {
            return Ok(res);
        }
        // Slow path: wait for the registry channel (TTY blocking task or the
        // expires_at watchdog will call `pending.resolve` when ready).
        let rx = self.pending.register(challenge_id);
        tokio::time::timeout(timeout, rx)
            .await
            .map_err(|_| OobError::Timeout)?
            .map_err(|_| OobError::Timeout)
    }

    async fn available(&self) -> bool {
        // Available when a controlling TTY can be opened for writing.
        // When auto-deny is active we still report available so the channel
        // can be dispatched (it fast-denies headlessly).
        if self.is_auto_deny() {
            return true;
        }
        #[cfg(unix)]
        {
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/tty")
                .is_ok()
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

/// Open the operator's controlling TTY for writing the prompt.
/// Falls back to stderr if `/dev/tty` cannot be opened.
fn open_tty_write() -> Box<dyn io::Write + Send> {
    #[cfg(unix)]
    {
        if let Ok(f) = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/tty")
        {
            return Box::new(f);
        }
    }
    Box::new(io::stderr())
}

/// Read a single character from the controlling TTY on a blocking thread.
/// Returns `'n'` as the safe default when TTY read fails.
fn read_key_from_tty() -> char {
    #[cfg(unix)]
    {
        use std::io::Read as _;
        if let Ok(mut f) = std::fs::OpenOptions::new().read(true).open("/dev/tty") {
            let mut buf = [0u8; 1];
            if f.read_exact(&mut buf).is_ok() {
                return buf[0] as char;
            }
        }
    }
    'n'
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use merkle_ports::OobNotifier as _;
    use merkle_types::{ChallengeId, OobChallengeOutcome};

    use super::TerminalPromptChannel;
    use crate::pending::PendingChallengeRegistry;

    fn cid(n: u8) -> ChallengeId {
        format!("018f4c1a-0000-7000-8000-0000000000{n:02x}")
            .parse()
            .expect("valid ChallengeId")
    }

    /// Auto-deny path: `new_auto_deny_for_test()` reports `available=true`
    /// and dispatch records Denied immediately without touching `/dev/tty`.
    #[tokio::test]
    async fn auto_deny_resolves_immediately() {
        let channel = TerminalPromptChannel::new_auto_deny_for_test();
        assert!(channel.available().await, "should be available in auto-deny mode");

        let challenge = make_challenge(cid(0x01));
        let device = make_device();

        channel
            .dispatch(&challenge, &device)
            .await
            .expect("dispatch must succeed");

        let res = channel
            .await_resolution(cid(0x01), Duration::from_secs(1))
            .await
            .expect("resolution must be delivered");

        assert_eq!(
            res.outcome,
            OobChallengeOutcome::Denied,
            "auto-deny must produce Denied outcome"
        );
    }

    /// Without auto-deny, `available()` reflects TTY accessibility.
    /// We cannot assert a fixed value in CI, but the method must not panic.
    #[tokio::test]
    async fn available_does_not_panic_in_ci() {
        let channel = TerminalPromptChannel::new();
        let _ = channel.available().await;
    }

    /// Registry integration: inject a resolution directly into the registry
    /// (simulating what dispatch does) and verify `await_resolution` delivers it.
    #[tokio::test]
    async fn registry_inject_delivers_resolution() {
        use merkle_domain_access_mediation::oob::resolution::OobResolution;
        use merkle_types::Rfc3339Timestamp;
        use std::sync::Arc;

        let registry = Arc::new(PendingChallengeRegistry::new());
        let id = cid(0x10);

        // Register before resolving (mirrors what await_resolution does).
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

    /// Auto-deny: `await_resolution` returns Denied (not Expired or Timeout).
    #[tokio::test]
    async fn auto_deny_outcome_is_denied_not_timeout() {
        let channel = TerminalPromptChannel::new_auto_deny_for_test();
        let challenge = make_challenge(cid(0x20));
        let device = make_device();

        channel.dispatch(&challenge, &device).await.expect("dispatch ok");

        let res = channel
            .await_resolution(cid(0x20), Duration::from_secs(1))
            .await
            .expect("resolution must succeed");

        assert_eq!(
            res.outcome,
            OobChallengeOutcome::Denied,
            "expected Denied, got {:?}",
            res.outcome
        );
    }

    // ---- helpers ----

    fn make_challenge(id: ChallengeId) -> merkle_domain_access_mediation::oob::challenge::OobChallenge {
        use merkle_types::{Handle, NamespaceId, OobChannel, Sensitivity};

        merkle_domain_access_mediation::oob::challenge::OobChallenge {
            challenge_id: id,
            namespace_id: "018f4c1a-0000-7000-8000-000000000010"
                .parse::<NamespaceId>()
                .expect("ns id"),
            secret_handle: "vault://prod/ssh-key/bastion".parse::<Handle>().expect("handle"),
            sensitivity: Sensitivity::High,
            oob_channel: OobChannel::TerminalPrompt,
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
