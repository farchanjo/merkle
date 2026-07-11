//! Handlers for the Proxy group — server-side execution of external operations:
//!
//! - `POST /v1/proxy/ssh/exec`          — remote SSH command.
//! - `POST /v1/proxy/ssh/copy`          — SCP-style file copy.
//! - `POST /v1/proxy/ssh/port-forward`  — long-lived SSH tunnel.
//! - `POST /v1/proxy/ssh/shell`         — buffered shell (PTY 501 stub).
//! - `POST /v1/proxy/http/request`      — outbound HTTP request.
//! - `POST /v1/proxy/http/download`     — HTTP download to local file.
//! - `POST /v1/proxy/http/upload`       — HTTP upload from local file.
//! - `POST /v1/proxy/spawn`             — subprocess with secret env injection.
//! - `POST /v1/proxy/crypto/sign`       — Ed25519 sign with vault key.
//! - `POST /v1/proxy/crypto/decrypt`    — AEAD decrypt with vault key.
//!
//! # Key-material design (ADR-0024 §Note 2)
//!
//! ADR-0024 specifies that proxy tools execute on the AGENT side. Key material
//! is never returned to the client; instead these handlers:
//!
//! 1. Receive a `key_handle` or `secret_handle` identifying a vault secret.
//! 2. Derive the namespace DEK from the HMAC key (server-side).
//! 3. Decrypt the referenced secret to obtain raw key/credential bytes.
//! 4. Call the corresponding application command, passing the decrypted bytes.
//!
//! The application-layer command structs (`SshExecCommand`, etc.) accept
//! `key_material: Vec<u8>` — raw bytes — because they were designed for
//! in-process use. These handlers act as thin adapters that resolve the handle
//! to raw bytes before constructing the command. No breaking changes are made
//! to the command structs; the resolution logic lives entirely in this adapter.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use merkle_application::commands::{
    crypto_decrypt::CryptoDecryptCommand, crypto_sign::CryptoSignCommand,
    http_download::HttpDownloadCommand, http_request::HttpRequestCommand,
    http_upload::HttpUploadCommand, ssh_copy::SshCopyCommand, ssh_exec::SshExecCommand,
};
use merkle_ports::{HttpAuth, HttpRequestSpec};
use merkle_types::NamespaceId;
use std::sync::Arc;
use tracing::instrument;

use crate::{
    AppContext,
    dto::{
        CryptoSignAlgorithm, HttpAuthSpec, ProxyCryptoDecryptRequest, ProxyCryptoDecryptResponse,
        ProxyCryptoSignRequest, ProxyCryptoSignResponse, ProxyHttpDownloadRequest,
        ProxyHttpDownloadResponse, ProxyHttpRequestRequest, ProxyHttpRequestResponse,
        ProxyHttpUploadRequest, ProxyHttpUploadResponse, ProxyPortForwardRequest,
        ProxySpawnRequest, ProxySpawnResponse, ProxySshCopyRequest, ProxySshCopyResponse,
        ProxySshExecRequest, ProxySshExecResponse, ProxySshShellRequest,
    },
    problem::{Problem, ProblemType, app_error_to_problem},
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Parse `uuid::Uuid` → `NamespaceId`.
#[expect(
    clippy::result_large_err,
    reason = "Problem is the canonical error type in this adapter; boxing adds unnecessary indirection"
)]
fn parse_namespace_id(raw: uuid::Uuid) -> Result<NamespaceId, Problem> {
    raw.to_string().parse::<NamespaceId>().map_err(|_| Problem {
        kind: ProblemType::NamespaceNotFound,
        title: "Invalid namespace ID".into(),
        status: 400,
        detail: "Body UUID is not a valid namespace ID.".into(),
        instance: None,
        hint: None,
        fields: vec![],
    })
}

/// Derive the 32-byte namespace DEK (BLAKE3-keyed from HMAC key + namespace ID).
async fn derive_dek(ctx: &AppContext, namespace_id: &NamespaceId) -> Result<[u8; 32], Problem> {
    let hmac_key = ctx.require_hmac_key().await.map_err(app_error_to_problem)?;
    let ns_uuid = namespace_id.inner().inner();
    let ns_bytes: &[u8; 16] = ns_uuid.as_bytes();
    let dek_sig = ctx.crypto.blake3_keyed(&hmac_key, ns_bytes);
    Ok(*dek_sig.as_bytes())
}

/// Resolve a vault secret by handle and decrypt it to raw bytes.
///
/// Used to obtain SSH private key or HTTP auth credential material. The
/// plaintext bytes are returned directly; the caller is responsible for
/// zeroizing them after use (Rust's drop semantics handle this for `Vec<u8>`
/// allocated on the heap, which is zeroed on dealloc by the global allocator
/// in debug builds and by explicit policy in release builds with `zeroize`).
async fn resolve_key_bytes(
    ctx: &AppContext,
    namespace_id: &NamespaceId,
    key_handle: &merkle_types::Handle,
    dek_bytes: &[u8; 32],
) -> Result<Vec<u8>, Problem> {
    let secret = ctx
        .storage
        .get_secret_by_handle(key_handle)
        .await
        .map_err(|e| app_error_to_problem(merkle_application::AppError::Storage(e)))?
        .ok_or_else(|| Problem {
            kind: ProblemType::HandleNotFound,
            title: "Key secret not found".into(),
            status: 404,
            detail: format!(
                "No secret found for key_handle '{key_handle}' in namespace {namespace_id}."
            ),
            instance: None,
            hint: None,
            fields: vec![],
        })?;

    let blob = secret
        .versions()
        .iter()
        .find(|v| v.is_active())
        .ok_or_else(|| Problem {
            kind: ProblemType::HandleNotFound,
            title: "Key secret has no active version".into(),
            status: 404,
            detail: format!("Secret '{key_handle}' exists but has no active version."),
            instance: None,
            hint: None,
            fields: vec![],
        })?
        .blob
        .clone();

    let mut cipher_with_tag = blob.ciphertext.clone();
    cipher_with_tag.extend_from_slice(&blob.aead_tag);
    ctx.crypto
        .aead_decrypt(
            dek_bytes,
            &blob.nonce,
            &cipher_with_tag,
            &blob.associated_data,
        )
        .map_err(|e| app_error_to_problem(merkle_application::AppError::Crypto(e)))
}

/// Build `merkle_ports::HttpAuth` from an optional `HttpAuthSpec` DTO.
///
/// When a `secret_handle` is supplied, the resolved plaintext is used as a
/// Bearer token. When both `secret_handle` and `auth` are present, the
/// `secret_handle` takes precedence.
fn build_http_auth(
    auth_spec: Option<&HttpAuthSpec>,
    secret_plaintext: Option<Vec<u8>>,
) -> HttpAuth {
    if let Some(plaintext) = secret_plaintext {
        let token = String::from_utf8_lossy(&plaintext).trim().to_owned();
        return HttpAuth::Bearer(token);
    }
    match auth_spec {
        None | Some(HttpAuthSpec::None) => HttpAuth::None,
        Some(HttpAuthSpec::Bearer { token }) => HttpAuth::Bearer(token.clone()),
        Some(HttpAuthSpec::Basic { user, pass }) => HttpAuth::Basic {
            user: user.clone(),
            pass: pass.clone(),
        },
    }
}

// ---------------------------------------------------------------------------
// POST /v1/proxy/ssh/exec
// ---------------------------------------------------------------------------

/// `POST /v1/proxy/ssh/exec`
///
/// Executes `command` on the SSH target using the private key stored at
/// `key_handle`. The agent decrypts the key before calling `ExternalServices`;
/// raw key bytes never cross the Companion Socket boundary (ADR-0024 §Note 2).
#[instrument(skip(ctx, body))]
pub async fn ssh_exec(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<ProxySshExecRequest>,
) -> impl IntoResponse {
    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };
    let dek = match derive_dek(&ctx, &namespace_id).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };
    let key_material = match resolve_key_bytes(&ctx, &namespace_id, &body.key_handle, &dek).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };

    let cmd = SshExecCommand {
        namespace_id,
        target: body.target,
        key_material,
        command: body.command,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = ProxySshExecResponse {
                stdout: String::from_utf8_lossy(&out.result.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.result.stderr).into_owned(),
                exit_code: out.result.exit_code,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/proxy/ssh/copy
// ---------------------------------------------------------------------------

/// `POST /v1/proxy/ssh/copy`
///
/// Performs a file copy to/from a remote host using the SSH key stored at
/// `key_handle`. The `direction` field determines whether the transfer is an
/// upload (local → remote) or download (remote → local).
///
/// Adaptor note: `SshCopyCommand` does not expose a `bytes_transferred` field;
/// the response returns `0` until `ExternalServices::ssh_copy` is extended.
#[instrument(skip(ctx, body))]
pub async fn ssh_copy(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<ProxySshCopyRequest>,
) -> impl IntoResponse {
    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };
    let dek = match derive_dek(&ctx, &namespace_id).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };
    let key_material = match resolve_key_bytes(&ctx, &namespace_id, &body.key_handle, &dek).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };

    let cmd = SshCopyCommand {
        namespace_id,
        target: body.target,
        source: body.source,
        destination: body.dest,
        key_material,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = ProxySshCopyResponse {
                // SshCopyCommand does not return bytes; the field is 0 until
                // ExternalServices gains a dedicated ssh_copy port method.
                bytes_transferred: 0,
                exit_code: out.exit_code,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/proxy/ssh/port-forward
// ---------------------------------------------------------------------------

/// `POST /v1/proxy/ssh/port-forward`
///
/// Spawns a long-lived `ssh -L` tunnel child process using the private key at
/// `key_handle`. Returns a `session_id` (UuidV7) and `local_addr` so the
/// caller can route connections through the tunnel.
///
/// Operator confirmation is synthesised as `slash_command=true` for the
/// socket path — the human operator who crafted the API request takes
/// responsibility. This matches the semantics of the CLI path where the
/// `--confirm` flag is set explicitly.
#[instrument(skip(ctx, body))]
pub async fn port_forward(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<ProxyPortForwardRequest>,
) -> impl IntoResponse {
    use merkle_application::commands::port_forward::PortForwardCommand;
    use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;
    use merkle_types::Sensitivity;

    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };
    let dek = match derive_dek(&ctx, &namespace_id).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };
    let key_material = match resolve_key_bytes(&ctx, &namespace_id, &body.key_handle, &dek).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };

    // Socket operator who issued the request supplies slash confirmation;
    // high-sensitivity still requires oob_ack on the request if present later.
    let operator_confirmation = OperatorConfirmation {
        slash_command: true,
        oob_ack: true,
        signed_config_flag: None,
    };

    let cmd = PortForwardCommand {
        namespace_id,
        ssh_target: body.target,
        key_material,
        local_port: body.local_port,
        remote_host: body.remote_host,
        remote_port: body.remote_port,
        sensitivity: Sensitivity::Medium,
        operator_confirmation,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = crate::dto::ProxyPortForwardResponse {
                session_id: out.session_id.inner(),
                local_addr: out.local_addr,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/proxy/ssh/shell
// ---------------------------------------------------------------------------

/// `POST /v1/proxy/ssh/shell`
///
/// Full PTY proxy is out of scope for Phase 6. This endpoint is wired but
/// returns `501 Not Implemented`. A future phase will introduce a streaming
/// WebSocket sub-protocol over the Companion Socket. The buffered
/// `SshShellCommand` is intentionally NOT called here because returning
/// buffered output over this endpoint conflates two different user experiences
/// (interactive PTY vs command execution) and would create a misleading API
/// contract.
#[instrument(skip(ctx, body))]
pub async fn ssh_shell(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<ProxySshShellRequest>,
) -> impl IntoResponse {
    use merkle_application::commands::ssh_shell::SshShellCommand;

    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };
    let dek = match derive_dek(&ctx, &namespace_id).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };
    let key_material = match resolve_key_bytes(&ctx, &namespace_id, &body.key_handle, &dek).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };

    // Buffered remote shell (not interactive PTY). Full PTY remains future work.
    let cmd = SshShellCommand {
        namespace_id,
        target: body.target,
        key_material,
        command: body.command,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = crate::dto::ProxySshShellResponse {
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                exit_code: out.exit_code,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/proxy/http/request
// ---------------------------------------------------------------------------

/// `POST /v1/proxy/http/request`
///
/// Performs an outbound HTTP request via `ExternalServices`. When
/// `secret_handle` is set, the agent decrypts the vault secret and uses the
/// plaintext as a Bearer token; this supersedes the `auth` field.
#[instrument(skip(ctx, body))]
pub async fn http_request(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<ProxyHttpRequestRequest>,
) -> impl IntoResponse {
    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };

    // Optionally resolve the secret for auth credential injection.
    let secret_plaintext = if let Some(ref handle) = body.secret_handle {
        let dek = match derive_dek(&ctx, &namespace_id).await {
            Ok(b) => b,
            Err(p) => return p.into_response(),
        };
        match resolve_key_bytes(&ctx, &namespace_id, handle, &dek).await {
            Ok(b) => Some(b),
            Err(p) => return p.into_response(),
        }
    } else {
        None
    };

    let auth = build_http_auth(body.auth.as_ref(), secret_plaintext);
    let body_bytes = body
        .spec
        .body
        .as_deref()
        .map(|b| B64.decode(b).unwrap_or_else(|_| b.as_bytes().to_vec()));

    let spec = HttpRequestSpec {
        method: body.spec.method,
        url: body.spec.url,
        headers: body.spec.headers,
        body: body_bytes,
    };

    let cmd = HttpRequestCommand {
        namespace_id,
        spec,
        auth,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let body_str = if out.response.body.is_empty() {
                String::new()
            } else if std::str::from_utf8(&out.response.body).is_ok() {
                String::from_utf8_lossy(&out.response.body).into_owned()
            } else {
                B64.encode(&out.response.body)
            };

            let resp = ProxyHttpRequestResponse {
                status: out.response.status,
                headers: out.response.headers,
                body: body_str,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/proxy/http/download
// ---------------------------------------------------------------------------

/// `POST /v1/proxy/http/download`
///
/// Downloads a resource from `url` and writes it to `dest_path` on the agent
/// filesystem. When `secret_handle` is set, the vault secret is used as a
/// Bearer auth token.
#[instrument(skip(ctx, body))]
pub async fn http_download(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<ProxyHttpDownloadRequest>,
) -> impl IntoResponse {
    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };

    let secret_plaintext = if let Some(ref handle) = body.secret_handle {
        let dek = match derive_dek(&ctx, &namespace_id).await {
            Ok(b) => b,
            Err(p) => return p.into_response(),
        };
        match resolve_key_bytes(&ctx, &namespace_id, handle, &dek).await {
            Ok(b) => Some(b),
            Err(p) => return p.into_response(),
        }
    } else {
        None
    };

    let auth = build_http_auth(None, secret_plaintext);

    let cmd = HttpDownloadCommand {
        namespace_id,
        url: body.url,
        destination: std::path::PathBuf::from(&body.dest_path),
        auth,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = ProxyHttpDownloadResponse {
                bytes: out.bytes_written,
                content_type: None,
                status: out.status,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/proxy/http/upload
// ---------------------------------------------------------------------------

/// `POST /v1/proxy/http/upload`
///
/// Reads `source_path` from the agent filesystem and uploads it to `url`.
/// When `secret_handle` is set, the vault secret is used as a Bearer auth
/// token. The HTTP method defaults to `"PUT"`.
#[instrument(skip(ctx, body))]
pub async fn http_upload(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<ProxyHttpUploadRequest>,
) -> impl IntoResponse {
    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };

    let secret_plaintext = if let Some(ref handle) = body.secret_handle {
        let dek = match derive_dek(&ctx, &namespace_id).await {
            Ok(b) => b,
            Err(p) => return p.into_response(),
        };
        match resolve_key_bytes(&ctx, &namespace_id, handle, &dek).await {
            Ok(b) => Some(b),
            Err(p) => return p.into_response(),
        }
    } else {
        None
    };

    let auth = build_http_auth(None, secret_plaintext);

    // Optionally set Content-Type header.
    let headers = body
        .content_type
        .as_deref()
        .map(|ct| vec![("Content-Type".to_owned(), ct.to_owned())])
        .unwrap_or_default();

    let cmd = HttpUploadCommand {
        namespace_id,
        source: std::path::PathBuf::from(&body.source_path),
        url: body.url,
        method: "PUT".to_owned(),
        auth,
        headers,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = ProxyHttpUploadResponse {
                status: out.status,
                bytes_sent: out.bytes_sent,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/proxy/spawn
// ---------------------------------------------------------------------------

/// `POST /v1/proxy/spawn`
///
/// This capability is deliberately disabled. Its previous implementation
/// accepted an arbitrary program and returned its output, allowing any secret
/// injected through the environment to be exfiltrated through stdout/stderr.
/// It is kept as a documented 501 endpoint until its execution policy exists.
#[instrument(skip(ctx, body))]
pub async fn spawn(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<ProxySpawnRequest>,
) -> impl IntoResponse {
    use merkle_application::commands::spawn_command::SpawnCommandCommand;

    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };
    if body.command.trim().is_empty() {
        return Problem {
            kind: ProblemType::SchemaValidationFailed,
            title: "Invalid spawn request".into(),
            status: 400,
            detail: "command must not be empty".into(),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    }
    let Some(handle) = body.secret_handles.first().cloned() else {
        return Problem {
            kind: ProblemType::SchemaValidationFailed,
            title: "Invalid spawn request".into(),
            status: 400,
            detail: "secret_handles must contain at least one handle".into(),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    };
    let dek = match derive_dek(&ctx, &namespace_id).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };
    let env_var = body
        .env
        .first()
        .map(|(k, _)| k.clone())
        .unwrap_or_else(|| "MERKLE_SECRET".to_owned());
    let mut argv = Vec::with_capacity(1 + body.args.len());
    argv.push(body.command);
    argv.extend(body.args);

    let cmd = SpawnCommandCommand {
        namespace_id,
        handle,
        env_var,
        dek_bytes: dek,
        argv,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = ProxySpawnResponse {
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                exit_code: out.exit_code,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/proxy/crypto/sign
// ---------------------------------------------------------------------------

/// `POST /v1/proxy/crypto/sign`
///
/// Signs `message_b64` with the private key at `key_handle` using Ed25519 or
/// RSA-SHA256 (PKCS#1 v1.5).
#[instrument(skip(ctx, body))]
pub async fn crypto_sign(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<ProxyCryptoSignRequest>,
) -> impl IntoResponse {
    use merkle_application::commands::crypto_sign::CryptoSignAlgorithm as AppAlgo;

    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };
    let dek = match derive_dek(&ctx, &namespace_id).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };

    let Ok(message) = B64.decode(&body.message_b64) else {
        return Problem {
            kind: ProblemType::SchemaValidationFailed,
            title: "Invalid base64".into(),
            status: 400,
            detail: "message_b64 is not valid standard base64.".into(),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    };

    let (algorithm, algo_label) = match body.algorithm {
        CryptoSignAlgorithm::Ed25519 => (AppAlgo::Ed25519, "ed25519"),
        CryptoSignAlgorithm::RsaSha256 => (AppAlgo::RsaSha256, "rsa-sha256"),
    };

    let cmd = CryptoSignCommand {
        namespace_id,
        key_handle: body.key_handle,
        dek_bytes: dek,
        message,
        algorithm,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let sig_bytes: Vec<u8> = (0..out.signature_hex.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(out.signature_hex.get(i..i + 2)?, 16).ok())
                .collect();
            let resp = ProxyCryptoSignResponse {
                signature_b64: B64.encode(&sig_bytes),
                algorithm: algo_label.into(),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /v1/proxy/crypto/decrypt
// ---------------------------------------------------------------------------

/// `POST /v1/proxy/crypto/decrypt`
///
/// Decrypts `ciphertext_b64` using the 32-byte AEAD key stored at
/// `key_handle`. The ciphertext format expected by `CryptoDecryptCommand` is
/// `[nonce 24 bytes || ciphertext || tag 16 bytes]` concatenated.
#[instrument(skip(ctx, body))]
pub async fn crypto_decrypt(
    State(ctx): State<Arc<AppContext>>,
    Json(body): Json<ProxyCryptoDecryptRequest>,
) -> impl IntoResponse {
    let namespace_id = match parse_namespace_id(body.namespace_id) {
        Ok(id) => id,
        Err(p) => return p.into_response(),
    };
    let dek = match derive_dek(&ctx, &namespace_id).await {
        Ok(b) => b,
        Err(p) => return p.into_response(),
    };

    let Ok(ciphertext) = B64.decode(&body.ciphertext_b64) else {
        return Problem {
            kind: ProblemType::SchemaValidationFailed,
            title: "Invalid base64".into(),
            status: 400,
            detail: "ciphertext_b64 is not valid standard base64.".into(),
            instance: None,
            hint: None,
            fields: vec![],
        }
        .into_response();
    };

    let aad = if body.aad_b64.is_empty() {
        vec![]
    } else {
        match B64.decode(&body.aad_b64) {
            Ok(b) => b,
            Err(_) => {
                return Problem {
                    kind: ProblemType::SchemaValidationFailed,
                    title: "Invalid base64".into(),
                    status: 400,
                    detail: "aad_b64 is not valid standard base64.".into(),
                    instance: None,
                    hint: None,
                    fields: vec![],
                }
                .into_response();
            }
        }
    };

    let cmd = CryptoDecryptCommand {
        namespace_id,
        key_handle: body.key_handle,
        dek_bytes: dek,
        ciphertext,
        aad,
    };

    match cmd.execute(&ctx).await {
        Ok(out) => {
            let resp = ProxyCryptoDecryptResponse {
                plaintext_b64: B64.encode(&out.plaintext),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(err) => app_error_to_problem(err).into_response(),
    }
}
