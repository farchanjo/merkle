//! Companion Socket HTTP client.
//!
//! Uses a custom [`UnixConnector`] built on top of `hyper-util` +
//! `tokio::net::UnixStream` to speak HTTP/1.1 over a Unix domain socket.
//! No TLS; isolation is the OS permission boundary (`0600` socket).

use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Context as _;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::net::UnixStream;
use tower::Service;

use crate::error::{CliError, ProblemDetail};

// ---------------------------------------------------------------------------
// Unix connector
// ---------------------------------------------------------------------------

/// A hyper-util `Connect` implementation that opens a `UnixStream` to the
/// configured socket path, ignoring the URI authority.
///
/// The wrapper uses `TokioIo` to bridge tokio's `AsyncRead`/`AsyncWrite`
/// traits with hyper's `rt::Read`/`rt::Write` traits.
#[derive(Debug, Clone)]
pub struct UnixConnector {
    socket_path: PathBuf,
}

impl UnixConnector {
    /// Create a connector that dials `socket_path` on every call.
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }
}

/// Newtype wrapper — `TokioIo<UnixStream>` implements `hyper::rt::Read` and
/// `hyper::rt::Write` automatically; we just need the `Connection` impl.
pub struct UnixStreamWrapper(TokioIo<UnixStream>);

impl Connection for UnixStreamWrapper {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

// Delegate hyper::rt::Read/Write to TokioIo.
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

impl Service<Uri> for UnixConnector {
    type Response = UnixStreamWrapper;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<UnixStreamWrapper, std::io::Error>> + Send>>;

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

// ---------------------------------------------------------------------------
// CompanionSocketClient
// ---------------------------------------------------------------------------

/// HTTP/1.1 client that talks to the Vault Agent over a Unix domain socket.
#[derive(Debug, Clone)]
pub struct CompanionSocketClient {
    inner: Client<UnixConnector, Full<Bytes>>,
}

impl CompanionSocketClient {
    /// Create a new client connected to `socket_path`.
    pub fn new(socket_path: PathBuf) -> Self {
        let connector = UnixConnector::new(socket_path);
        let inner = Client::builder(TokioExecutor::new()).build(connector);
        Self { inner }
    }

    /// Issue a `GET` request and deserialize the JSON response body.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, CliError> {
        let uri: Uri = format!("http://localhost{path}")
            .parse()
            .with_context(|| format!("invalid URI path: {path}"))?;

        let response = self.inner.get(uri).await.map_err(|e| {
            CliError::AgentUnreachable(e.to_string())
        })?;

        self.decode_response(response).await
    }

    /// Issue a `POST` request with a JSON body and deserialize the response.
    pub async fn post<S: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &S,
    ) -> Result<T, CliError> {
        let uri: Uri = format!("http://localhost{path}")
            .parse()
            .with_context(|| format!("invalid URI path: {path}"))?;

        let json_bytes = serde_json::to_vec(body)
            .with_context(|| "serialising request body")?;

        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(json_bytes)))
            .with_context(|| "building POST request")?;

        let response = self.inner.request(request).await.map_err(|e| {
            CliError::AgentUnreachable(e.to_string())
        })?;

        self.decode_response(response).await
    }

    /// Issue a `DELETE` request with an optional JSON body.
    pub async fn delete<S: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: Option<&S>,
    ) -> Result<T, CliError> {
        let uri: Uri = format!("http://localhost{path}")
            .parse()
            .with_context(|| format!("invalid URI path: {path}"))?;

        let (content_type_hdr, body_bytes) = match body {
            Some(b) => {
                let bytes = serde_json::to_vec(b)
                    .with_context(|| "serialising DELETE body")?;
                (Some("application/json"), Bytes::from(bytes))
            }
            None => (None, Bytes::new()),
        };

        let mut builder = hyper::Request::builder()
            .method(hyper::Method::DELETE)
            .uri(uri);

        if let Some(ct) = content_type_hdr {
            builder = builder.header("Content-Type", ct);
        }

        let request = builder
            .body(Full::new(body_bytes))
            .with_context(|| "building DELETE request")?;

        let response = self.inner.request(request).await.map_err(|e| {
            CliError::AgentUnreachable(e.to_string())
        })?;

        self.decode_response(response).await
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    async fn decode_response<T: DeserializeOwned>(
        &self,
        response: hyper::Response<hyper::body::Incoming>,
    ) -> Result<T, CliError> {
        let status = response.status();
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| CliError::AgentUnreachable(e.to_string()))?
            .to_bytes();

        if status == hyper::StatusCode::SERVICE_UNAVAILABLE {
            // Try to detect "sealed" state from the problem+json body.
            if let Ok(problem) = serde_json::from_slice::<ProblemDetail>(&body_bytes) {
                if problem.problem_type.contains("sealed")
                    || problem.title.to_lowercase().contains("sealed")
                {
                    return Err(CliError::Sealed);
                }
                return Err(CliError::AgentError {
                    status: status.as_u16(),
                    title: problem.title,
                    detail: problem.detail,
                });
            }
        }

        if !status.is_success() {
            let problem: ProblemDetail = serde_json::from_slice(&body_bytes).unwrap_or(
                ProblemDetail {
                    problem_type: String::new(),
                    title: format!("HTTP {status}"),
                    detail: String::from_utf8_lossy(&body_bytes).into_owned(),
                    status: status.as_u16(),
                },
            );
            return Err(CliError::AgentError {
                status: status.as_u16(),
                title: problem.title,
                detail: problem.detail,
            });
        }

        serde_json::from_slice::<T>(&body_bytes).map_err(CliError::Json)
    }
}
