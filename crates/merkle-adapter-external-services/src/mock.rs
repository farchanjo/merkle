//! In-process mock for [`merkle_ports::ExternalServices`].
//!
//! Suitable for unit tests and integration test harnesses where a real SSH
//! host or HTTP server is not available.  Responses are pre-loaded at
//! construction time via the builder API.

use std::collections::VecDeque;

use async_trait::async_trait;
use parking_lot::Mutex;

use merkle_ports::{
    ExternalError, ExternalServices, HttpAuth, HttpRequestSpec, HttpResponse, SshExecOutput,
};

/// A mock implementation of [`ExternalServices`] that returns pre-loaded
/// responses in the order they were enqueued.
///
/// # Panics
///
/// Panics if a method is called and the corresponding response queue is empty.
///
/// # Example
///
/// ```
/// use merkle_adapter_external_services::MockExternalServices;
/// use merkle_ports::{SshExecOutput, HttpResponse};
///
/// let mock = MockExternalServices::new()
///     .with_ssh_response(SshExecOutput {
///         stdout: b"uptime output".to_vec(),
///         stderr: vec![],
///         exit_code: 0,
///     });
/// ```
#[derive(Debug, Default)]
pub struct MockExternalServices {
    ssh_responses: Mutex<VecDeque<Result<SshExecOutput, ExternalError>>>,
    http_responses: Mutex<VecDeque<Result<HttpResponse, ExternalError>>>,
}

impl MockExternalServices {
    /// Create a new mock with empty queues.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue a successful SSH response.
    #[must_use]
    pub fn with_ssh_response(self, output: SshExecOutput) -> Self {
        self.ssh_responses.lock().push_back(Ok(output));
        self
    }

    /// Enqueue an SSH error response.
    #[must_use]
    pub fn with_ssh_error(self, err: ExternalError) -> Self {
        self.ssh_responses.lock().push_back(Err(err));
        self
    }

    /// Enqueue a successful HTTP response.
    #[must_use]
    pub fn with_http_response(self, response: HttpResponse) -> Self {
        self.http_responses.lock().push_back(Ok(response));
        self
    }

    /// Enqueue an HTTP error response.
    #[must_use]
    pub fn with_http_error(self, err: ExternalError) -> Self {
        self.http_responses.lock().push_back(Err(err));
        self
    }
}

#[async_trait]
impl ExternalServices for MockExternalServices {
    async fn ssh_exec(
        &self,
        _target: &str,
        _key_material: &[u8],
        _command: &str,
    ) -> Result<SshExecOutput, ExternalError> {
        self.ssh_responses
            .lock()
            .pop_front()
            .expect("MockExternalServices: ssh_exec called but response queue is empty")
    }

    async fn http_request(
        &self,
        _req: HttpRequestSpec,
        _auth: HttpAuth,
    ) -> Result<HttpResponse, ExternalError> {
        self.http_responses
            .lock()
            .pop_front()
            .expect("MockExternalServices: http_request called but response queue is empty")
    }
}
