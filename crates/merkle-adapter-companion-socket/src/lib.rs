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

pub mod dto;
pub mod error;
pub mod extensions;
pub mod handlers;
pub mod peer_cred;
pub mod problem;
pub mod router;

use std::path::PathBuf;
use std::sync::Arc;

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
        // Remove stale socket from previous run, if present.
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        info!(
            socket = %self.socket_path.display(),
            "companion socket listening"
        );

        let app = router::build(Arc::clone(&self.app_ctx));
        axum::serve(listener, app).await?;

        Ok(())
    }
}
