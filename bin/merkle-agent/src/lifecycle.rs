//! Lifecycle helpers — sealed/unsealed transition coordination.
//!
//! This module provides the platform-specific signal setup (`SIGTERM` on
//! Unix) used by the main run loop to trigger graceful shutdown, and the
//! `sd_notify` call that marks the agent as ready to the systemd service
//! manager on Linux.
//!
//! ## Shutdown sequence (from `docs/arch/operations/lifecycle.md` §7)
//!
//! 1. Stop accepting new connections (socket server drops its `serve` loop).
//! 2. Drain MCP sessions (wait up to 10 s).
//! 3. Cancel background workers (allow up to 5 s).
//! 4. Trigger backup if pending.
//! 5. Flush audit log; fsync.
//! 6. Save AnacronState.
//! 7. Wipe keys (handled by `VaultIdentity::shutdown`).
//! 8. Exit zero.
//!
//! In Phase 4 the drain and wipe steps are stubs; the token cancellation
//! propagates through all tasks and the 30-second join timeout in `run.rs`
//! provides the hard deadline.

use anyhow::Context as _;
use tokio_util::sync::CancellationToken;
use tracing::info;

// ---------------------------------------------------------------------------
// Signal setup
// ---------------------------------------------------------------------------

/// Wait for SIGINT (Ctrl-C) or SIGTERM and then cancel the shutdown token.
///
/// On Unix, both `SIGINT` and `SIGTERM` trigger shutdown.
/// On Windows / other platforms, only `ctrl_c` (SIGINT) is used.
///
/// # Errors
///
/// Returns an error if the OS signal handler cannot be installed.
pub async fn wait_for_shutdown(shutdown: CancellationToken) -> anyhow::Result<()> {
    wait_for_os_signal().await.context("signal handler error")?;

    info!("shutdown signal received; cancelling tasks");
    shutdown.cancel();
    Ok(())
}

#[cfg(unix)]
async fn wait_for_os_signal() -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm =
        signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("failed to install SIGHUP handler")?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received");
        }
        _ = sigterm.recv() => {
            info!("SIGTERM received");
        }
        _ = sighup.recv() => {
            info!("SIGHUP received; treating as graceful shutdown");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_os_signal() -> anyhow::Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("failed to wait for Ctrl-C")?;
    info!("Ctrl-C received");
    Ok(())
}

// ---------------------------------------------------------------------------
// Service-manager readiness notification
// ---------------------------------------------------------------------------

/// Notify the service manager (systemd / launchd / SCM) that the agent is
/// ready to accept connections.
///
/// On Linux with systemd, sends `READY=1` via `sd_notify(3)`. On other
/// platforms this is a no-op.
pub fn notify_ready() {
    #[cfg(target_os = "linux")]
    {
        // Attempt to notify systemd without pulling in `libsystemd-dev`.
        // The `sd_notify` protocol sends a datagram to the path in
        // `$NOTIFY_SOCKET`. If the variable is unset we are not running
        // under systemd and can skip silently.
        if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
            use std::os::unix::net::UnixDatagram;
            if let Ok(sock) = UnixDatagram::unbound() {
                let _ = sock.send_to(b"READY=1", socket_path.trim_start_matches('@'));
            }
        }
    }

    tracing::debug!("service-manager readiness notified (READY=1 if applicable)");
}
