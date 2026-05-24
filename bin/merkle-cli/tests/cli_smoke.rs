//! Integration smoke tests for the `merkle` CLI binary.
//!
//! # Running
//!
//! Most tests in this file require a running Vault Agent and are gated
//! behind `#[ignore]`. Run them explicitly with:
//!
//! ```sh
//! # Start the agent first:
//! #   merkle init && merkle agent &
//! cargo test -p merkle-cli -- --include-ignored
//! ```
//!
//! The `MERKLE_SOCKET` env var can override the default socket path:
//!
//! ```sh
//! MERKLE_SOCKET=/tmp/test-merkle.sock cargo test -p merkle-cli -- --include-ignored
//! ```

use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::UnixStream;
use tower::Service;

// ---------------------------------------------------------------------------
// Unix connector for integration tests
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SmokeConnector {
    socket_path: PathBuf,
}

struct SmokeStream(TokioIo<UnixStream>);

impl Connection for SmokeStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for SmokeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for SmokeStream {
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

impl Service<hyper::Uri> for SmokeConnector {
    type Response = SmokeStream;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<SmokeStream, std::io::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: hyper::Uri) -> Self::Future {
        let path = self.socket_path.clone();
        Box::pin(async move {
            let stream = UnixStream::connect(&path).await?;
            Ok(SmokeStream(TokioIo::new(stream)))
        })
    }
}

fn resolve_socket() -> PathBuf {
    if let Ok(s) = std::env::var("MERKLE_SOCKET") {
        return PathBuf::from(s);
    }
    if cfg!(target_os = "macos") {
        let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_owned());
        PathBuf::from(tmpdir).join("merkle").join("companion.sock")
    } else {
        PathBuf::from("/run/merkle/companion.sock")
    }
}

async fn get_json(path: &str) -> anyhow::Result<serde_json::Value> {
    let socket = resolve_socket();
    let connector = SmokeConnector { socket_path: socket };
    let client: Client<SmokeConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let uri: hyper::Uri = format!("http://localhost{path}").parse()?;
    let resp = client.get(uri).await?;
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok(serde_json::from_slice(&bytes)?)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Smoke test: `GET /v1/agent/status` must return a `sealed` field.
#[tokio::test]
#[ignore = "requires running Vault Agent — set MERKLE_SOCKET if non-default"]
async fn status_endpoint_returns_sealed_field() {
    let value = get_json("/v1/agent/status")
        .await
        .expect("GET /v1/agent/status");

    assert!(
        value.get("sealed").is_some(),
        "response must contain 'sealed' field, got: {value}"
    );
}

/// Smoke test: the agent must respond to consecutive status calls.
#[tokio::test]
#[ignore = "requires running Vault Agent — set MERKLE_SOCKET if non-default"]
async fn consecutive_status_calls_succeed() {
    for i in 0..3u32 {
        let value = get_json("/v1/agent/status")
            .await
            .unwrap_or_else(|e| panic!("call {i} failed: {e}"));
        assert!(value.get("sealed").is_some(), "call {i} missing 'sealed'");
    }
}

/// Smoke test: `GET /v1/namespaces` must return an `items` array.
#[tokio::test]
#[ignore = "requires running + unsealed Vault Agent"]
async fn list_namespaces_returns_items() {
    let value = get_json("/v1/namespaces")
        .await
        .expect("GET /v1/namespaces");

    assert!(
        value.get("items").and_then(|v| v.as_array()).is_some(),
        "response must contain 'items' array, got: {value}"
    );
}
