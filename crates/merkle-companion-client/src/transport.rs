//! Unix domain socket transport layer for hyper-util.
//!
//! [`UnixConnector`] implements the hyper-util `Connect` trait by dialling a
//! Unix domain socket path. [`UnixStreamWrapper`] bridges Tokio's
//! `AsyncRead`/`AsyncWrite` to hyper's `rt::Read`/`rt::Write` traits.
//!
//! The Companion Socket uses no TLS; isolation is enforced by the OS
//! `0600` permission boundary on the socket file and by the peer-credential
//! middleware running inside the agent.

use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tower::Service;

// ---------------------------------------------------------------------------
// UnixConnector
// ---------------------------------------------------------------------------

/// A hyper-util `Connect` implementation that opens a [`UnixStream`] to the
/// configured socket path, ignoring the URI authority component.
#[derive(Debug, Clone)]
pub struct UnixConnector {
    socket_path: PathBuf,
}

impl UnixConnector {
    /// Create a connector that dials `socket_path` on every call.
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }
}

// ---------------------------------------------------------------------------
// UnixStreamWrapper
// ---------------------------------------------------------------------------

/// Newtype over [`TokioIo<UnixStream>`] that adds the [`Connection`] impl
/// required by hyper-util's legacy client.
///
/// `TokioIo<UnixStream>` already bridges Tokio's async I/O traits to hyper's
/// `rt::Read`/`rt::Write`; we only need to declare the connection as
/// non-proxied.
pub struct UnixStreamWrapper(pub(crate) TokioIo<UnixStream>);

impl Connection for UnixStreamWrapper {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for UnixStreamWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for UnixStreamWrapper {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Service impl
// ---------------------------------------------------------------------------

impl Service<Uri> for UnixConnector {
    type Response = UnixStreamWrapper;
    type Error = std::io::Error;
    type Future = Pin<
        Box<dyn std::future::Future<Output = Result<UnixStreamWrapper, std::io::Error>> + Send>,
    >;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Uri) -> Self::Future {
        let path = self.socket_path.clone();
        Box::pin(async move {
            let stream = UnixStream::connect(&path).await?;
            Ok(UnixStreamWrapper(TokioIo::new(stream)))
        })
    }
}
