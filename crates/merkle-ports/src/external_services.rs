//! [`ExternalServices`] driven port — SSH Bridge and HTTP Bridge.
//!
//! Provides the domain with a uniform interface to remote execution and HTTP
//! calls. The adapter implementation is deferred; no concrete adapter crate
//! exists in Phase 1.

use crate::error::ExternalError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Output captured from a remote SSH command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshExecOutput {
    /// Bytes written to standard output by the remote command.
    pub stdout: Vec<u8>,
    /// Bytes written to standard error by the remote command.
    pub stderr: Vec<u8>,
    /// The exit code returned by the remote process.
    pub exit_code: i32,
}

/// Parameters for a single outbound HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestSpec {
    /// HTTP method string (e.g. `"GET"`, `"POST"`).
    pub method: String,
    /// Absolute URL of the request target.
    pub url: String,
    /// Additional request headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Optional request body bytes.
    pub body: Option<Vec<u8>>,
}

/// Authentication credential to attach to an HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpAuth {
    /// Bearer token sent in the `Authorization` header.
    Bearer(String),
    /// HTTP Basic authentication credential.
    Basic {
        /// Username component of the Basic credential.
        user: String,
        /// Password component of the Basic credential.
        pass: String,
    },
    /// No authentication; the request is sent as-is.
    None,
}

/// A received HTTP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    /// HTTP status code (e.g. `200`, `404`).
    pub status: u16,
    /// Response headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// Driven port for external service integrations (SSH Bridge, HTTP Bridge).
#[async_trait]
pub trait ExternalServices: Send + Sync {
    /// Execute `command` on a remote host via SSH.
    ///
    /// `target` is a `host:port` string. `key_material` is the PEM-encoded
    /// private key used for authentication.
    async fn ssh_exec(
        &self,
        target: &str,
        key_material: &[u8],
        command: &str,
    ) -> Result<SshExecOutput, ExternalError>;

    /// Perform an outbound HTTP request.
    ///
    /// `auth` is merged into the request before it is sent.
    async fn http_request(
        &self,
        req: HttpRequestSpec,
        auth: HttpAuth,
    ) -> Result<HttpResponse, ExternalError>;
}
