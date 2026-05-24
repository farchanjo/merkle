//! # merkle-adapter-external-services
//!
//! **Driven-port adapter** — implements [`merkle_ports::ExternalServices`].
//!
//! Provides:
//!
//! - [`ExternalServicesAdapter`] — production adapter that executes real SSH
//!   commands (subprocess path via tempfile identity) and real HTTP requests
//!   (via `reqwest` + rustls).
//! - [`MockExternalServices`] — in-process mock for tests; returns pre-loaded
//!   responses from a queue.
//!
//! ## Security contract
//!
//! Key material (`key_material: &[u8]`) is written to a `tempfile::NamedTempFile`
//! with mode `0600` for the duration of the `ssh` subprocess call.  The file is
//! unlinked automatically when the `NamedTempFile` guard is dropped.  Key bytes
//! are never returned to callers or included in tracing spans.
//!
//! HTTP auth values are applied as `Authorization` headers inside this adapter;
//! only the auth variant (bearer/basic/none) is recorded in tracing spans.

mod http;
mod mock;
mod ssh;

pub use mock::MockExternalServices;

use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use tracing::instrument;

use merkle_ports::{
    ExternalError, ExternalServices, HttpAuth, HttpRequestSpec, HttpResponse, SshExecOutput,
};

/// Timeout applied to each SSH exec operation when none is configured.
const SSH_DEFAULT_TIMEOUT: Duration = ssh::DEFAULT_TIMEOUT;

/// Production implementation of [`ExternalServices`].
///
/// Uses a shared `reqwest::Client` (connection pool + rustls) for HTTP and
/// spawns an `ssh` subprocess for SSH exec operations.
///
/// # Construction
///
/// ```
/// use merkle_adapter_external_services::ExternalServicesAdapter;
///
/// let adapter = ExternalServicesAdapter::new();
/// ```
///
/// To customise the SSH timeout:
///
/// ```
/// use std::time::Duration;
/// use merkle_adapter_external_services::ExternalServicesAdapter;
///
/// let adapter = ExternalServicesAdapter::with_ssh_timeout(Duration::from_secs(60));
/// ```
#[derive(Debug)]
pub struct ExternalServicesAdapter {
    http_client: Client,
    ssh_timeout: Duration,
}

impl ExternalServicesAdapter {
    /// Create an adapter with default settings (SSH timeout: 30 s).
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest::Client` cannot be built (e.g., TLS
    /// initialisation failure — highly unlikely in normal environments).
    #[must_use]
    pub fn new() -> Self {
        Self::with_ssh_timeout(SSH_DEFAULT_TIMEOUT)
    }

    /// Create an adapter with a custom SSH exec timeout.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest::Client` cannot be built.
    #[must_use]
    pub fn with_ssh_timeout(ssh_timeout: Duration) -> Self {
        let http_client = Client::builder()
            .use_rustls_tls()
            .build()
            .expect("reqwest::Client build should never fail under normal conditions");
        Self {
            http_client,
            ssh_timeout,
        }
    }
}

impl Default for ExternalServicesAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ExternalServices for ExternalServicesAdapter {
    #[instrument(skip(self, key_material), fields(target = %target, command = %command))]
    async fn ssh_exec(
        &self,
        target: &str,
        key_material: &[u8],
        command: &str,
    ) -> Result<SshExecOutput, ExternalError> {
        ssh::ssh_exec(target, key_material, command, self.ssh_timeout).await
    }

    #[instrument(skip(self, req, auth), fields(url = %req.url, method = %req.method))]
    async fn http_request(
        &self,
        req: HttpRequestSpec,
        auth: HttpAuth,
    ) -> Result<HttpResponse, ExternalError> {
        http::http_request(&self.http_client, req, auth).await
    }
}
