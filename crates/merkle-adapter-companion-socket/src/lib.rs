//! # merkle-adapter-companion-socket
//!
//! **Driving-port adapter** — Companion Socket: the single inbound driving
//! port for the Vault Agent domain.
//!
//! Exposes 19 HTTP/1.1 endpoints over a Unix domain socket (or Windows named
//! pipe stub), routing requests to the `merkle-application` command handlers.
//! Callers are authenticated by platform peer-credential check before any
//! handler body executes.
//!
//! ## Architecture
//!
//! ```text
//! CLI / MCP Adapter
//!       │  HTTP/1.1 over Unix domain socket
//!       ▼
//! CompanionSocketServer
//!   ├── peer_cred middleware   ← OS-level UID/PID check
//!   ├── axum Router (19 routes)
//!   └── handlers → AppContext → application layer
//! ```
//!
//! ## Security
//!
//! Every accepted connection is checked via [`peer_cred`] before the axum
//! router sees the request. Connections that fail the UID check are dropped
//! immediately with no HTTP response.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod consumer_gate;
/// Public HTTP DTO contract shared with external clients.
pub use merkle_companion_contract as dto;
pub mod error;
pub mod extensions;
pub mod handlers;
pub mod peer_cred;
pub mod problem;
pub mod router;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use tokio::net::UnixListener;
use tracing::info;

pub use error::CompanionError;
pub use merkle_application::AppContext;

/// The Companion Socket HTTP server.
///
/// Binds to a Unix domain socket path and serves all 19 endpoints defined in
/// `companion-socket.yaml`. Incoming connections are authenticated by peer
/// credential before routing begins.
///
/// # Example
///
/// ```no_run
/// use std::path::PathBuf;
/// use std::sync::Arc;
/// use merkle_adapter_companion_socket::CompanionSocketServer;
/// use merkle_adapter_companion_socket::AppContext;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     // ctx is constructed by the binary entry point with concrete adapters.
///     # let ctx: Arc<AppContext> = unimplemented!();
///     let server = CompanionSocketServer::new(
///         PathBuf::from("/run/merkle/companion.sock"),
///         ctx,
///     );
///     server.serve().await
/// }
/// ```
pub struct CompanionSocketServer {
    socket_path: PathBuf,
    app_ctx: Arc<AppContext>,
}

impl CompanionSocketServer {
    /// Create a new server bound to `socket_path` with the given application
    /// context.
    #[must_use]
    pub fn new(socket_path: PathBuf, ctx: Arc<AppContext>) -> Self {
        Self {
            socket_path,
            app_ctx: ctx,
        }
    }

    /// Bind the Unix socket and begin serving connections.
    ///
    /// Removes any stale socket file at `socket_path` before binding.
    /// Runs until the process is killed or an unrecoverable I/O error occurs.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the socket cannot be bound or if `axum::serve` exits
    /// with an I/O error.
    pub async fn serve(self) -> anyhow::Result<()> {
        let listener = self.bind()?;
        self.serve_listener(listener).await
    }

    /// Bind the Unix socket with no window in which another user could connect
    /// to an over-permissive socket.
    ///
    /// The original `bind()` → `set_permissions(0600)` sequence left a TOCTOU
    /// window: between the kernel creating the socket inode (with `0666 & !umask`
    /// permissions) and the explicit `chmod`, a process owned by another user
    /// could `connect()` and reach the handlers before the per-connection
    /// peer-credential check tightened things. GAP-007 closes that window with
    /// two independent mitigations, applied *before* the bind:
    ///
    /// 1. The socket's parent directory is forced to `0700`, so no other user
    ///    can even traverse to the socket inode during the window.
    /// 2. A restrictive `umask` (`0o177`) makes the socket itself `0600` at
    ///    creation time; the subsequent explicit `chmod` is defence in depth.
    ///
    /// # Errors
    ///
    /// Returns `Err` if a stale socket cannot be removed, the parent directory
    /// cannot be created/hardened, or the bind fails.
    pub fn bind(&self) -> anyhow::Result<UnixListener> {
        Self::bind_hardened(&self.socket_path)
    }

    /// Serve an already-bound listener. Splitting bind from serve lets the
    /// composition root report readiness only after the agent is actually
    /// able to accept authenticated Companion Socket connections.
    pub async fn serve_listener(self, listener: UnixListener) -> anyhow::Result<()> {
        info!(
            socket = %self.socket_path.display(),
            "companion socket listening"
        );
        let app = router::build(Arc::clone(&self.app_ctx));
        serve_with_peer_cred(listener, app).await
    }

    fn bind_hardened(socket_path: &std::path::Path) -> anyhow::Result<UnixListener> {
        // Remove stale socket from previous run, if present.
        if socket_path.exists() {
            std::fs::remove_file(socket_path)
                .with_context(|| format!("remove stale socket {}", socket_path.display()))?;
        }

        #[cfg(unix)]
        harden_parent_dir(socket_path)?;

        // Hold a restrictive umask across the bind; restored on drop.
        #[cfg(unix)]
        let _umask = UmaskGuard::owner_only();

        let listener = UnixListener::bind(socket_path)
            .with_context(|| format!("bind companion socket {}", socket_path.display()))?;

        // Defence in depth: umask only clears bits, so pin the mode explicitly.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 socket {}", socket_path.display()))?;
        }

        Ok(listener)
    }
}

/// Force the socket's parent directory to `0700` (owner-only traverse) before
/// the socket is bound, eliminating the TOCTOU window around the bind.
#[cfg(unix)]
fn harden_parent_dir(socket_path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    if let Some(parent) = socket_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create socket directory {}", parent.display()))?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 socket directory {}", parent.display()))?;
    }
    Ok(())
}

/// RAII guard that tightens the process `umask` for the duration of a socket
/// bind and restores the previous value on drop.
#[cfg(unix)]
struct UmaskGuard(libc::mode_t);

#[cfg(unix)]
impl UmaskGuard {
    /// Set the umask to `0o177` so any file created during the guard's lifetime
    /// is at most `0600`, capturing the previous mask for restoration.
    fn owner_only() -> Self {
        // SAFETY: `umask(2)` is infallible and only reads/replaces the calling
        // process's file-mode-creation mask, returning the previous value. It
        // has no preconditions and touches no shared or aliased memory.
        #[expect(
            unsafe_code,
            reason = "umask(2) has no safe Rust wrapper; blocked on adding nix/rustix to the workspace dependency set."
        )]
        let prev = unsafe { libc::umask(0o177) };
        Self(prev)
    }
}

#[cfg(unix)]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: restore the previously captured mask; identical contract to
        // `owner_only` above.
        #[expect(
            unsafe_code,
            reason = "umask(2) has no safe Rust wrapper; blocked on adding nix/rustix to the workspace dependency set."
        )]
        unsafe {
            libc::umask(self.0);
        }
    }
}

/// Serve the companion socket, authenticating every connection by OS peer
/// credentials extracted at accept time.
///
/// Unlike `axum::serve`, this injects the verified
/// [`peer_cred::PeerCredentials`] into each request's extensions BEFORE the
/// router runs, so the `peer_cred_check` middleware sees real credentials and
/// can fail closed. A connection whose credentials cannot be extracted from the
/// kernel is dropped immediately with no HTTP response.
///
/// # Errors
///
/// Returns `Err` only if the listener itself fails irrecoverably; per-connection
/// errors are logged and do not abort the accept loop.
pub async fn serve_with_peer_cred(listener: UnixListener, app: axum::Router) -> anyhow::Result<()> {
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;
    use tower::ServiceExt as _;
    use tracing::{debug, warn};

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "companion socket accept failed");
                continue;
            }
        };

        // Extract OS peer credentials at accept time. FAIL CLOSED: if the
        // kernel call fails, drop the connection rather than serve it
        // unauthenticated.
        let creds = match peer_cred::extract(&stream) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                warn!(error = %e, "peer credential extraction failed; dropping connection");
                continue;
            }
        };

        let app = app.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            // Per-connection service: inject the verified credentials into every
            // request BEFORE the router (and its peer_cred_check middleware).
            let svc = tower::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let app = app.clone();
                let creds = Arc::clone(&creds);
                async move {
                    let mut req = req.map(axum::body::Body::new);
                    req.extensions_mut().insert(creds);
                    app.oneshot(req).await
                }
            });
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, TowerToHyperService::new(svc))
                .await
            {
                debug!(error = %e, "companion connection closed with error");
            }
        });
    }
}

#[cfg(all(test, unix))]
mod bind_hardening_tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::CompanionSocketServer;

    /// GAP-007: the parent directory is locked to `0700` and the socket to
    /// `0600`, leaving no window for another user to connect.
    #[tokio::test]
    async fn bind_hardened_sets_0700_parent_and_0600_socket() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("run/merkle");
        let sock = dir.join("agent.sock");

        let listener = CompanionSocketServer::bind_hardened(&sock).expect("bind");

        let dir_mode = std::fs::metadata(&dir)
            .expect("dir meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "parent dir must be 0700, got {dir_mode:o}");

        let sock_mode = std::fs::metadata(&sock)
            .expect("sock meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(sock_mode, 0o600, "socket must be 0600, got {sock_mode:o}");

        drop(listener);
    }

    /// A stale socket file from a previous run is replaced, not an error.
    #[tokio::test]
    async fn bind_hardened_replaces_stale_socket() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sock = tmp.path().join("agent.sock");
        std::fs::write(&sock, b"stale").expect("write stale");

        let listener = CompanionSocketServer::bind_hardened(&sock).expect("bind over stale");
        let sock_mode = std::fs::metadata(&sock)
            .expect("sock meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(sock_mode, 0o600);
        drop(listener);
    }
}
