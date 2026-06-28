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

mod destination_policy;
mod dns_guard;
mod http;
mod mock;
mod ssh;

pub use destination_policy::DestinationPolicy;
pub use mock::MockExternalServices;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use tracing::instrument;

use crate::dns_guard::ValidatingDnsResolver;

use merkle_ports::{
    ExternalError, ExternalServices, HttpAuth, HttpRequestSpec, HttpResponse, SshExecOutput,
};

/// Timeout applied to each SSH exec operation when none is configured.
const SSH_DEFAULT_TIMEOUT: Duration = ssh::DEFAULT_TIMEOUT;

/// Overall per-request timeout for the shared HTTP client.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Connection-establishment timeout for the shared HTTP client.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the hardened shared HTTP client: rustls, explicit request + connect
/// timeouts, redirects disabled (a 3xx must not be auto-followed to an
/// unvalidated — possibly internal — host with the credential still attached),
/// and a [`ValidatingDnsResolver`] so every hostname connect is screened
/// through the same egress denylist as pre-flight validation. The resolver
/// closes the TOCTOU DNS-rebinding gap: the IP `reqwest` actually dials is
/// re-checked against `is_forbidden_ip`, so a host that rebinds to an internal
/// address after validation still fails closed.
fn build_http_client() -> Client {
    Client::builder()
        .use_rustls_tls()
        .timeout(HTTP_REQUEST_TIMEOUT)
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(ValidatingDnsResolver))
        .build()
        .expect("reqwest::Client build should never fail under normal conditions")
}

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
    http_policy: DestinationPolicy,
    ssh_timeout: Duration,
}

impl ExternalServicesAdapter {
    /// Create an adapter with default settings (SSH timeout: 30 s, strict HTTP
    /// egress policy).
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest::Client` cannot be built (e.g., TLS
    /// initialisation failure — highly unlikely in normal environments).
    #[must_use]
    pub fn new() -> Self {
        Self::with_ssh_timeout(SSH_DEFAULT_TIMEOUT)
    }

    /// Create an adapter with a custom SSH exec timeout and the strict HTTP
    /// egress policy.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest::Client` cannot be built.
    #[must_use]
    pub fn with_ssh_timeout(ssh_timeout: Duration) -> Self {
        Self::with_config(ssh_timeout, DestinationPolicy::strict())
    }

    /// Create an adapter with an explicit SSH timeout and HTTP egress policy.
    ///
    /// Production callers should use [`DestinationPolicy::strict`]; the
    /// permissive policy exists only for local mock-server integration tests.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest::Client` cannot be built.
    #[must_use]
    pub fn with_config(ssh_timeout: Duration, http_policy: DestinationPolicy) -> Self {
        Self {
            http_client: build_http_client(),
            http_policy,
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
        http::http_request(&self.http_client, &self.http_policy, req, auth).await
    }
}
