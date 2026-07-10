//! [`CompanionSocketClient`] — typed HTTP client for the Companion Socket API.
//!
//! Provides generic low-level methods ([`get`], [`post`], [`delete`]) and typed
//! wrappers for all 19 Companion Socket endpoints. Both the CLI and the MCP
//! adapter consume this client; neither needs to hand-craft HTTP requests.
//!
//! # Example
//!
//! ```no_run
//! use std::path::PathBuf;
//! use merkle_companion_client::CompanionSocketClient;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = CompanionSocketClient::new(PathBuf::from("/run/merkle/companion.sock"));
//!     let status = client.agent_status().await?;
//!     println!("vault state: {:?}", status.vault_state);
//!     Ok(())
//! }
//! ```

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::Uri;
use hyper::body::{Bytes, Incoming};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

/// Default per-request deadline. A hung or wedged daemon must never hang the
/// caller (CLI or MCP process) indefinitely.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Long deadline for ceremonies that touch the file keystore (scrypt work
/// factor 18) or encrypt large dual-recipient backups. File-backend `init`
/// routinely exceeds 30 s on cold stores.
const LONG_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Hard ceiling on a response body. The Companion Socket only ever returns
/// small JSON envelopes; a runaway or malicious body must not be able to OOM
/// the client process.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Percent-encode a query-string value so it cannot inject extra parameters
/// (`&`, `=`) or break the request line. `NON_ALPHANUMERIC` is intentionally
/// aggressive — every reserved and unsafe byte is escaped.
fn enc(value: &str) -> impl std::fmt::Display + '_ {
    utf8_percent_encode(value, NON_ALPHANUMERIC)
}

use merkle_companion_contract::{
    AgentStatusResponse, AuditQuery, AuditResponse, BackupSnapshotDto, CloseSessionResponse,
    CreateRestorePlanRequest, CreateSessionRequest, CreateSessionResponse, DeleteSecretRequest,
    DeleteSecretResponse, DoctorResponse, ExecuteRestoreRequest, ExecuteRestoreResponse,
    InitVaultRequest, InitVaultResponse, ListNamespacesResponse, ListSecretVersionsResponse,
    ListSecretsParams, ListSecretsResponse, ListSnapshotsParams, ListSnapshotsResponse,
    OobPendingResponse, ProxyCryptoDecryptRequest, ProxyCryptoDecryptResponse,
    ProxyCryptoSignRequest, ProxyCryptoSignResponse, ProxyHttpDownloadRequest,
    ProxyHttpDownloadResponse, ProxyHttpRequestRequest, ProxyHttpRequestResponse,
    ProxyHttpUploadRequest, ProxyHttpUploadResponse, ProxyPortForwardRequest,
    ProxyPortForwardResponse, ProxySpawnRequest, ProxySpawnResponse, ProxySshCopyRequest,
    ProxySshCopyResponse, ProxySshExecRequest, ProxySshExecResponse, ProxySshShellRequest,
    ProxySshShellResponse, PutSecretRequest, PutSecretResponse, RestorePlanResponse,
    RevealAuthorizationResponse, RevealRequest, RevokeTempfileResponse, RollbackSecretRequest,
    RotateSecretRequest, RotateSecretResponse, SealResponse, SecretDto, TriggerBackupRequest,
    UnsealRequest, UnsealResponse, UseFifoResponse, UseTempfileResponse, UseTokenRequest,
    UseTokenResponse, WriteFifoRequest, WriteTempfileRequest,
};

use crate::error::{ClientError, ProblemDetail};
use crate::transport::UnixConnector;

// ---------------------------------------------------------------------------
// RevealOutcome
// ---------------------------------------------------------------------------

/// The two possible success outcomes of `POST /v1/reveal`.
///
/// The server returns `200 OK` when plaintext is available immediately and
/// `202 Accepted` when OOB confirmation is still pending. Both are modelled
/// as success from the transport perspective; the caller branches on the
/// variant.
#[derive(Debug, Clone)]
pub enum RevealOutcome {
    /// Plaintext returned immediately (HTTP 200).
    Plaintext(RevealAuthorizationResponse),
    /// OOB confirmation pending (HTTP 202); retry after acknowledgement.
    OobPending(OobPendingResponse),
}

// ---------------------------------------------------------------------------
// CompanionSocketClient
// ---------------------------------------------------------------------------

/// HTTP/1.1 client that speaks to the Vault Agent Companion Socket over a
/// Unix domain socket.
///
/// Constructing the client is cheap — it creates the underlying hyper-util
/// connection pool but does not open any socket until the first request.
#[derive(Debug, Clone)]
pub struct CompanionSocketClient {
    inner: Client<UnixConnector, Full<Bytes>>,
}

impl CompanionSocketClient {
    /// Create a new client targeting `socket_path`.
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        let connector = UnixConnector::new(socket_path);
        let inner = Client::builder(TokioExecutor::new()).build(connector);
        Self { inner }
    }

    // -----------------------------------------------------------------------
    // Generic transport helpers
    // -----------------------------------------------------------------------

    /// Send a request with a deadline so a wedged daemon can never hang the
    /// caller indefinitely.
    async fn send(
        &self,
        request: hyper::Request<Full<Bytes>>,
    ) -> Result<hyper::Response<Incoming>, ClientError> {
        self.send_with_timeout(request, REQUEST_TIMEOUT).await
    }

    async fn send_with_timeout(
        &self,
        request: hyper::Request<Full<Bytes>>,
        timeout: Duration,
    ) -> Result<hyper::Response<Incoming>, ClientError> {
        match tokio::time::timeout(timeout, self.inner.request(request)).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(ClientError::Unreachable(e.to_string())),
            Err(_) => Err(ClientError::Timeout(timeout.as_secs())),
        }
    }

    /// Read a response body with a hard size ceiling so a runaway or malicious
    /// body cannot OOM the client process.
    async fn read_body(
        response: hyper::Response<Incoming>,
    ) -> Result<(hyper::StatusCode, Bytes), ClientError> {
        let status = response.status();
        let bytes = Limited::new(response.into_body(), MAX_BODY_BYTES)
            .collect()
            .await
            .map_err(|e| {
                if e.downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some()
                {
                    ClientError::BodyTooLarge(MAX_BODY_BYTES)
                } else {
                    ClientError::Unreachable(e.to_string())
                }
            })?
            .to_bytes();
        Ok((status, bytes))
    }

    /// Issue a `GET` request and deserialise the JSON response body.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on network failure, non-success HTTP status, or
    /// JSON deserialisation failure.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let uri: Uri = format!("http://localhost{path}")
            .parse()
            .with_context(|| format!("invalid URI path: {path}"))?;

        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
            .with_context(|| "building GET request")?;

        let response = self.send(request).await?;
        self.decode_response(response).await
    }

    /// Issue a `POST` request with a JSON body and deserialise the response.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on network failure, non-success HTTP status, or
    /// JSON (de)serialisation failure.
    pub async fn post<S: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &S,
    ) -> Result<T, ClientError> {
        self.post_with_timeout(path, body, REQUEST_TIMEOUT).await
    }

    /// Like [`post`](Self::post) but with an explicit request deadline.
    ///
    /// Use [`LONG_REQUEST_TIMEOUT`]-class values for init / backup against a
    /// file keystore (scrypt).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on network failure, non-success HTTP status, or
    /// JSON (de)serialisation failure.
    pub async fn post_with_timeout<S: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &S,
        timeout: Duration,
    ) -> Result<T, ClientError> {
        let uri: Uri = format!("http://localhost{path}")
            .parse()
            .with_context(|| format!("invalid URI path: {path}"))?;

        let json_bytes = serde_json::to_vec(body).with_context(|| "serialising request body")?;

        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(json_bytes)))
            .with_context(|| "building POST request")?;

        let response = self.send_with_timeout(request, timeout).await?;
        self.decode_response(response).await
    }

    /// Deadline used for vault init and on-demand backup (file-keystore scrypt).
    #[must_use]
    pub const fn long_request_timeout() -> Duration {
        LONG_REQUEST_TIMEOUT
    }

    /// Issue a `DELETE` request with an optional JSON body.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on network failure, non-success HTTP status, or
    /// JSON (de)serialisation failure.
    pub async fn delete<S: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: Option<&S>,
    ) -> Result<T, ClientError> {
        let uri: Uri = format!("http://localhost{path}")
            .parse()
            .with_context(|| format!("invalid URI path: {path}"))?;

        let (content_type_hdr, body_bytes) = match body {
            Some(b) => {
                let bytes = serde_json::to_vec(b).with_context(|| "serialising DELETE body")?;
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

        let response = self.send(request).await?;
        self.decode_response(response).await
    }

    // -----------------------------------------------------------------------
    // Internal: decode an HTTP response
    // -----------------------------------------------------------------------

    async fn decode_response<T: DeserializeOwned>(
        &self,
        response: hyper::Response<hyper::body::Incoming>,
    ) -> Result<T, ClientError> {
        let (status, body_bytes) = Self::read_body(response).await?;

        if status == hyper::StatusCode::SERVICE_UNAVAILABLE
            && let Ok(problem) = serde_json::from_slice::<ProblemDetail>(&body_bytes)
        {
            if problem.problem_type.contains("sealed")
                || problem.title.to_lowercase().contains("sealed")
            {
                return Err(ClientError::Sealed);
            }
            return Err(ClientError::Http {
                status: status.as_u16(),
                problem,
            });
        }

        if !status.is_success() {
            let problem =
                serde_json::from_slice::<ProblemDetail>(&body_bytes).unwrap_or(ProblemDetail {
                    problem_type: String::new(),
                    title: format!("HTTP {status}"),
                    detail: String::from_utf8_lossy(&body_bytes).into_owned(),
                    status: status.as_u16(),
                });
            return Err(ClientError::Http {
                status: status.as_u16(),
                problem,
            });
        }

        serde_json::from_slice::<T>(&body_bytes).map_err(ClientError::Json)
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Agent
    // -----------------------------------------------------------------------

    /// `POST /v1/agent/init` — initialise the vault.
    ///
    /// Returns a one-time recovery key that the operator must store offline.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn agent_init(
        &self,
        req: InitVaultRequest,
    ) -> Result<InitVaultResponse, ClientError> {
        // File keystore scrypt routinely exceeds the default 30 s deadline.
        self.post_with_timeout("/v1/agent/init", &req, LONG_REQUEST_TIMEOUT)
            .await
    }

    /// `GET /v1/agent/status` — health and diagnostic snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn agent_status(&self) -> Result<AgentStatusResponse, ClientError> {
        self.get("/v1/agent/status").await
    }

    /// `POST /v1/agent/unseal` — unlock the vault with keychain or passphrase.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn agent_unseal(&self, req: UnsealRequest) -> Result<UnsealResponse, ClientError> {
        self.post("/v1/agent/unseal", &req).await
    }

    /// `POST /v1/agent/seal` — lock the vault in-memory key.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn agent_seal(&self) -> Result<SealResponse, ClientError> {
        // Seal takes no body; send an empty JSON object.
        self.post("/v1/agent/seal", &serde_json::json!({})).await
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Namespaces
    // -----------------------------------------------------------------------

    /// `GET /v1/namespaces` — list all namespaces in this vault installation.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn list_namespaces(&self) -> Result<ListNamespacesResponse, ClientError> {
        self.get("/v1/namespaces").await
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Secrets
    // -----------------------------------------------------------------------

    /// `GET /v1/namespaces/{namespace_id}/secrets` — list secrets with optional
    /// filters.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn list_secrets(
        &self,
        namespace_id: Uuid,
        params: &ListSecretsParams,
    ) -> Result<ListSecretsResponse, ClientError> {
        let mut path = format!(
            "/v1/namespaces/{namespace_id}/secrets?limit={}",
            params.limit
        );
        if let Some(ref cat) = params.category {
            let _ = write!(path, "&category={}", enc(cat));
        }
        // BUG-006: the `tags` filter is parsed into `ListSecretsParams` by the MCP
        // adapter but was never serialized here, so `vault.list {tags:[…]}` was a
        // silent no-op end-to-end. The list handler consumes `params.tags`
        // (comma-separated `key:value`), so forward it.
        if let Some(ref tags) = params.tags {
            let _ = write!(path, "&tags={}", enc(tags));
        }
        if let Some(ref pat) = params.name_pattern {
            let _ = write!(path, "&name_pattern={}", enc(pat));
        }
        if let Some(ref cur) = params.cursor {
            let _ = write!(path, "&cursor={}", enc(cur));
        }
        if let Some(ref fts) = params.fts_query {
            let _ = write!(path, "&fts_query={}", enc(fts));
        }
        if params.offset > 0 {
            let _ = write!(path, "&offset={}", params.offset);
        }
        self.get(&path).await
    }

    /// `POST /v1/namespaces/{namespace_id}/secrets` — store a new secret.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn put_secret(
        &self,
        namespace_id: Uuid,
        req: PutSecretRequest,
    ) -> Result<PutSecretResponse, ClientError> {
        self.post(&format!("/v1/namespaces/{namespace_id}/secrets"), &req)
            .await
    }

    /// `GET /v1/namespaces/{namespace_id}/secrets/{handle_encoded}` — fetch secret metadata.
    ///
    /// `handle_encoded` must be a percent-encoded `vault://` URI string.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn get_secret(
        &self,
        namespace_id: Uuid,
        handle_encoded: &str,
    ) -> Result<SecretDto, ClientError> {
        self.get(&format!(
            "/v1/namespaces/{namespace_id}/secrets/{handle_encoded}"
        ))
        .await
    }

    /// `DELETE /v1/namespaces/{namespace_id}/secrets/{handle_encoded}` — permanently
    /// delete a secret and all its versions.
    ///
    /// `handle_encoded` must be a percent-encoded `vault://` URI string.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn delete_secret(
        &self,
        namespace_id: Uuid,
        handle_encoded: &str,
        req: DeleteSecretRequest,
    ) -> Result<DeleteSecretResponse, ClientError> {
        self.delete(
            &format!("/v1/namespaces/{namespace_id}/secrets/{handle_encoded}"),
            Some(&req),
        )
        .await
    }

    /// `GET /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/versions` — version
    /// history for a secret.
    ///
    /// `handle_encoded` must be a percent-encoded `vault://` URI string.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn list_secret_versions(
        &self,
        namespace_id: Uuid,
        handle_encoded: &str,
    ) -> Result<ListSecretVersionsResponse, ClientError> {
        self.get(&format!(
            "/v1/namespaces/{namespace_id}/secrets/{handle_encoded}/versions"
        ))
        .await
    }

    /// `POST /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rotate` — rotate
    /// the secret value and retain the previous version.
    ///
    /// `handle_encoded` must be a percent-encoded `vault://` URI string.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn rotate_secret(
        &self,
        namespace_id: Uuid,
        handle_encoded: &str,
        req: RotateSecretRequest,
    ) -> Result<RotateSecretResponse, ClientError> {
        self.post(
            &format!("/v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rotate"),
            &req,
        )
        .await
    }

    /// `POST /v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rollback` — roll
    /// the active version back to a previous one.
    ///
    /// `handle_encoded` must be a percent-encoded `vault://` URI string.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn rollback_secret(
        &self,
        namespace_id: Uuid,
        handle_encoded: &str,
        req: RollbackSecretRequest,
    ) -> Result<merkle_companion_contract::RollbackSecretResponse, ClientError> {
        self.post(
            &format!("/v1/namespaces/{namespace_id}/secrets/{handle_encoded}/rollback"),
            &req,
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Sessions
    // -----------------------------------------------------------------------

    /// `POST /v1/sessions` — open a new operator session.
    ///
    /// Sessions bind to a working-directory hash and resolve the active
    /// namespace via that hash.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn create_session(
        &self,
        req: CreateSessionRequest,
    ) -> Result<CreateSessionResponse, ClientError> {
        self.post("/v1/sessions", &req).await
    }

    /// `DELETE /v1/sessions/{session_id}` — close a session and revoke its
    /// short-lived use-tokens.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn close_session(
        &self,
        session_id: Uuid,
    ) -> Result<CloseSessionResponse, ClientError> {
        self.delete::<(), CloseSessionResponse>(&format!("/v1/sessions/{session_id}"), None)
            .await
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Reveal
    // -----------------------------------------------------------------------

    /// `POST /v1/reveal` — decrypt and reveal a secret's plaintext.
    ///
    /// Returns [`RevealOutcome::Plaintext`] when the server responds `200 OK`
    /// (all confirmation gates passed) or [`RevealOutcome::OobPending`] when
    /// the server responds `202 Accepted` (OOB confirmation still outstanding).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure. A `4xx` response
    /// (e.g. missing operator confirmation) surfaces as [`ClientError::Http`].
    pub async fn reveal(&self, req: RevealRequest) -> Result<RevealOutcome, ClientError> {
        let uri: Uri = "http://localhost/v1/reveal"
            .parse()
            .with_context(|| "invalid reveal URI")?;

        let json_bytes = serde_json::to_vec(&req).with_context(|| "serialising reveal body")?;

        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(json_bytes)))
            .with_context(|| "building reveal request")?;

        let response = self.send(request).await?;
        let (status, body_bytes) = Self::read_body(response).await?;

        if status == hyper::StatusCode::OK {
            let resp = serde_json::from_slice::<RevealAuthorizationResponse>(&body_bytes)
                .map_err(ClientError::Json)?;
            return Ok(RevealOutcome::Plaintext(resp));
        }

        if status == hyper::StatusCode::ACCEPTED {
            let resp = serde_json::from_slice::<OobPendingResponse>(&body_bytes)
                .map_err(ClientError::Json)?;
            return Ok(RevealOutcome::OobPending(resp));
        }

        // Non-success: parse problem+json or synthesise one.
        let problem =
            serde_json::from_slice::<ProblemDetail>(&body_bytes).unwrap_or(ProblemDetail {
                problem_type: String::new(),
                title: format!("HTTP {status}"),
                detail: String::from_utf8_lossy(&body_bytes).into_owned(),
                status: status.as_u16(),
            });
        Err(ClientError::Http {
            status: status.as_u16(),
            problem,
        })
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Audit
    // -----------------------------------------------------------------------

    /// `GET /v1/audit` — query the audit log with optional filters.
    ///
    /// `query` fields are serialised as HTTP query string parameters.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn query_audit(&self, query: &AuditQuery) -> Result<AuditResponse, ClientError> {
        let mut path = format!("/v1/audit?limit={}", query.limit);
        if let Some(ref op) = query.op {
            let _ = write!(path, "&op={}", enc(op));
        }
        if let Some(ref h) = query.handle {
            let _ = write!(path, "&handle={}", enc(h));
        }
        if let Some(ref outcome) = query.outcome {
            let _ = write!(path, "&outcome={}", enc(outcome));
        }
        if let Some(session_id) = query.session_id {
            let _ = write!(path, "&session_id={session_id}");
        }
        if query.verify_chain {
            path.push_str("&verify_chain=true");
        }
        self.get(&path).await
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Backup / Restore
    // -----------------------------------------------------------------------

    /// `POST /v1/backup` — trigger an on-demand encrypted backup.
    ///
    /// Returns the metadata of the newly created snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn trigger_backup(
        &self,
        req: TriggerBackupRequest,
    ) -> Result<BackupSnapshotDto, ClientError> {
        self.post("/v1/backup", &req).await
    }

    /// `GET /v1/backup/snapshots` — list available backup snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn list_snapshots(
        &self,
        params: &ListSnapshotsParams,
    ) -> Result<ListSnapshotsResponse, ClientError> {
        let mut path = format!("/v1/backup/snapshots?limit={}", params.limit);
        if let Some(ref cur) = params.cursor {
            let _ = write!(path, "&cursor={}", enc(cur));
        }
        self.get(&path).await
    }

    /// `POST /v1/backup/restore-plan` — validate a snapshot and generate a
    /// preview restore plan.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn create_restore_plan(
        &self,
        req: CreateRestorePlanRequest,
    ) -> Result<RestorePlanResponse, ClientError> {
        self.post("/v1/backup/restore-plan", &req).await
    }

    /// `POST /v1/backup/restore` — apply a previously created restore plan.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn execute_restore(
        &self,
        req: ExecuteRestoreRequest,
    ) -> Result<ExecuteRestoreResponse, ClientError> {
        self.post("/v1/backup/restore", &req).await
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Diagnostics
    // -----------------------------------------------------------------------

    /// `GET /v1/agent/doctor` — run a health-check sweep on the vault agent.
    ///
    /// Returns a structured list of named checks with pass/warn/fail status.
    /// Always returns a response, even in degraded state.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn agent_doctor(&self) -> Result<DoctorResponse, ClientError> {
        self.get("/v1/agent/doctor").await
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Use-tokens
    // -----------------------------------------------------------------------

    /// `POST /v1/use-tokens` — mint a short-lived use token for a secret.
    ///
    /// The token authorises the bearer to read the secret's plaintext once
    /// (or until it expires). The plaintext itself is never returned here.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn mint_use_token(
        &self,
        req: UseTokenRequest,
    ) -> Result<UseTokenResponse, ClientError> {
        self.post("/v1/use-tokens", &req).await
    }

    /// `POST /v1/use-tokens/tempfile` — write a secret into a mode-0600 temp
    /// file and return an opaque token referencing it.
    ///
    /// The real filesystem path is managed by the agent and never returned.
    /// The token must be used by the caller to reference the file in subsequent
    /// operations. The file is cleaned up when the session closes or the token
    /// is explicitly revoked.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn write_tempfile(
        &self,
        req: WriteTempfileRequest,
    ) -> Result<UseTempfileResponse, ClientError> {
        self.post("/v1/use-tokens/tempfile", &req).await
    }

    /// `POST /v1/use-tokens/fifo` — write a secret into a named FIFO and
    /// return an opaque token referencing it.
    ///
    /// The agent writes the plaintext once; the FIFO is removed after the first
    /// successful read. Suitable for programs that open a credential path exactly
    /// once (e.g. `ssh -i $(fifo_path)`).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn write_fifo(&self, req: WriteFifoRequest) -> Result<UseFifoResponse, ClientError> {
        self.post("/v1/use-tokens/fifo", &req).await
    }

    /// `DELETE /v1/use-tokens/tempfiles/{opaque_token}` — explicitly revoke a
    /// tempfile before session close.
    ///
    /// The file is removed immediately and the opaque token becomes invalid.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn revoke_tempfile(
        &self,
        opaque_token: &str,
    ) -> Result<RevokeTempfileResponse, ClientError> {
        self.delete::<(), RevokeTempfileResponse>(
            &format!("/v1/use-tokens/tempfiles/{opaque_token}"),
            None,
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Proxy / SSH
    // -----------------------------------------------------------------------

    /// `POST /v1/proxy/ssh/exec` — execute a remote command over SSH using a
    /// key-material secret stored in the vault.
    ///
    /// The private key is decrypted agent-side; key bytes never cross the socket.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn proxy_ssh_exec(
        &self,
        req: ProxySshExecRequest,
    ) -> Result<ProxySshExecResponse, ClientError> {
        self.post("/v1/proxy/ssh/exec", &req).await
    }

    /// `POST /v1/proxy/ssh/copy` — copy a file to or from a remote host using
    /// an SSH key secret.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn proxy_ssh_copy(
        &self,
        req: ProxySshCopyRequest,
    ) -> Result<ProxySshCopyResponse, ClientError> {
        self.post("/v1/proxy/ssh/copy", &req).await
    }

    /// `POST /v1/proxy/ssh/port-forward` — establish an SSH port tunnel using
    /// an SSH key secret.
    ///
    /// Returns a `session_id` and the bound `local_addr` on success.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn proxy_ssh_port_forward(
        &self,
        req: ProxyPortForwardRequest,
    ) -> Result<ProxyPortForwardResponse, ClientError> {
        self.post("/v1/proxy/ssh/port-forward", &req).await
    }

    /// `POST /v1/proxy/ssh/shell` — open an interactive SSH shell session.
    ///
    /// Full PTY streaming is not yet implemented server-side. The agent returns
    /// 501 Not Implemented; this wrapper propagates that as
    /// [`ClientError::Http { status: 501, .. }`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn proxy_ssh_shell(
        &self,
        req: ProxySshShellRequest,
    ) -> Result<ProxySshShellResponse, ClientError> {
        self.post("/v1/proxy/ssh/shell", &req).await
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Proxy / HTTP
    // -----------------------------------------------------------------------

    /// `POST /v1/proxy/http/request` — perform an HTTP request, optionally
    /// injecting credentials from a vault secret.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn proxy_http_request(
        &self,
        req: ProxyHttpRequestRequest,
    ) -> Result<ProxyHttpRequestResponse, ClientError> {
        self.post("/v1/proxy/http/request", &req).await
    }

    /// `POST /v1/proxy/http/download` — download a file to the agent
    /// filesystem, optionally using a vault secret for auth.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn proxy_http_download(
        &self,
        req: ProxyHttpDownloadRequest,
    ) -> Result<ProxyHttpDownloadResponse, ClientError> {
        self.post("/v1/proxy/http/download", &req).await
    }

    /// `POST /v1/proxy/http/upload` — upload a file from the agent filesystem
    /// to a URL, optionally using a vault secret for auth.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn proxy_http_upload(
        &self,
        req: ProxyHttpUploadRequest,
    ) -> Result<ProxyHttpUploadResponse, ClientError> {
        self.post("/v1/proxy/http/upload", &req).await
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Proxy / Spawn
    // -----------------------------------------------------------------------

    /// `POST /v1/proxy/spawn` — spawn a child process on the agent host with
    /// vault secrets injected as environment variables.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn proxy_spawn(
        &self,
        req: ProxySpawnRequest,
    ) -> Result<ProxySpawnResponse, ClientError> {
        self.post("/v1/proxy/spawn", &req).await
    }

    // -----------------------------------------------------------------------
    // Typed endpoint wrappers — Proxy / Crypto
    // -----------------------------------------------------------------------

    /// `POST /v1/proxy/crypto/sign` — sign a message using a private key stored
    /// as a vault secret.
    ///
    /// The signing key is decrypted agent-side; key bytes never cross the socket.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn proxy_crypto_sign(
        &self,
        req: ProxyCryptoSignRequest,
    ) -> Result<ProxyCryptoSignResponse, ClientError> {
        self.post("/v1/proxy/crypto/sign", &req).await
    }

    /// `POST /v1/proxy/crypto/decrypt` — decrypt ciphertext using an AEAD key
    /// stored as a vault secret.
    ///
    /// The decryption key is used agent-side; key bytes never cross the socket.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or server failure.
    pub async fn proxy_crypto_decrypt(
        &self,
        req: ProxyCryptoDecryptRequest,
    ) -> Result<ProxyCryptoDecryptResponse, ClientError> {
        self.post("/v1/proxy/crypto/decrypt", &req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exact wire sample for `GET /v1/agent/doctor`
    /// (`docs/arch/integrations/openapi/companion-socket.yaml` →
    /// `DoctorResponse`) — six checks, all passing, `overall: "healthy"`.
    const DOCTOR_SAMPLE: &str = r#"{
        "checks": [
            {"name": "vault_state", "status": "pass", "message": "unsealed", "duration_ms": 0},
            {"name": "audit_chain_integrity", "status": "pass", "message": "entries_checked=241", "duration_ms": 4},
            {"name": "storage_liveness", "status": "pass", "duration_ms": 1},
            {"name": "oob_notifier", "status": "pass", "duration_ms": 0},
            {"name": "fts5_consistency", "status": "pass", "message": "columns: name, tags, description, category, namespace_label; weights: 10.0, 5.0, 3.0, 2.0, 1.0", "duration_ms": 2},
            {"name": "keystore_backend", "status": "pass", "message": "os", "duration_ms": 0}
        ],
        "overall": "healthy"
    }"#;

    #[test]
    fn doctor_response_deserializes_from_wire_sample() {
        let doctor: DoctorResponse =
            serde_json::from_str(DOCTOR_SAMPLE).expect("doctor sample must deserialize");

        assert_eq!(doctor.checks.len(), 6);
        assert_eq!(doctor.overall, "healthy");

        assert_eq!(doctor.checks[0].name, "vault_state");
        assert_eq!(doctor.checks[0].status, "pass");
        assert_eq!(doctor.checks[0].message.as_deref(), Some("unsealed"));
        assert_eq!(doctor.checks[0].duration_ms, 0);

        // `storage_liveness` and `oob_notifier` omit `message` on the wire —
        // the DTO must treat the field as optional, not required.
        assert!(doctor.checks[2].message.is_none());
        assert!(doctor.checks[3].message.is_none());

        assert_eq!(doctor.checks[5].name, "keystore_backend");
        assert_eq!(doctor.checks[5].message.as_deref(), Some("os"));
    }

    #[test]
    fn doctor_response_round_trips_through_serialize() {
        let doctor: DoctorResponse =
            serde_json::from_str(DOCTOR_SAMPLE).expect("doctor sample must deserialize");

        let reserialized = serde_json::to_string(&doctor).expect("serialize doctor response");
        let round_tripped: DoctorResponse =
            serde_json::from_str(&reserialized).expect("re-deserialize doctor response");

        assert_eq!(round_tripped.overall, doctor.overall);
        assert_eq!(round_tripped.checks.len(), doctor.checks.len());
        // `message: None` must round-trip as an absent field, not `null`
        // (`#[serde(skip_serializing_if = "Option::is_none")]` on `DoctorCheck`).
        assert!(!reserialized.contains("\"message\":null"));
    }
}
