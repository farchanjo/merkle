//! Proxy tools: vault.ssh.exec, vault.ssh.copy, vault.ssh.port_forward,
//! vault.ssh.shell, vault.http.request, vault.http.download,
//! vault.http.upload, vault.spawn, vault.crypto.sign, vault.crypto.decrypt.
//!
//! All proxy commands are forwarded to the Vault Agent Companion Socket via
//! [`CompanionSocketClient`](merkle_companion_client::CompanionSocketClient).
//! Key material is decrypted agent-side; no key bytes cross the socket.
//!
//! `vault.ssh.shell` is wired but returns `vault.not_implemented` because
//! the server endpoint returns 501 Not Implemented in this phase.

use std::collections::HashMap;

use base64::Engine as _;
use rmcp::{
    ErrorData,
    handler::server::{router::tool::ToolRouter, tool::Parameters},
    model::{CallToolResult, Content},
    schemars::{self, JsonSchema},
    tool,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{MerkleMcpServer, errors::client_error_to_mcp};
use merkle_companion_client::dto::{
    HttpRequestSpecDto, ProxyCryptoDecryptRequest, ProxyCryptoSignRequest,
    ProxyHttpDownloadRequest, ProxyHttpRequestRequest, ProxyHttpUploadRequest,
    ProxyPortForwardRequest, ProxySpawnRequest, ProxySshCopyRequest, ProxySshExecRequest,
    ProxySshShellRequest, SshCopyDirection,
};
use merkle_types::Handle;

// ---------------------------------------------------------------------------
// SSH tool inputs
// ---------------------------------------------------------------------------

/// Input for vault.ssh.exec.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultSshExecInput {
    /// Handle URI of an ssh-category Secret containing the private key.
    pub handle: String,
    /// SSH target in `host:port` form (e.g. `"bastion.example.com:22"`).
    pub target: String,
    /// Command to execute on the remote host.
    pub command: String,
    /// Optional command arguments.
    pub args: Option<Vec<String>>,
    /// Optional environment variables for the remote process.
    pub env: Option<HashMap<String, String>>,
    /// Command timeout in seconds (default: 30).
    pub timeout_secs: Option<u32>,
}

/// Input for vault.ssh.copy.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultSshCopyInput {
    /// Handle URI of an ssh-category Secret.
    pub handle: String,
    /// SSH target in `host:port` form.
    pub target: String,
    /// Transfer direction: upload | download.
    pub direction: String,
    /// Source path (local for upload, remote for download).
    pub source: String,
    /// Destination path (remote for upload, local for download).
    pub dest: String,
}

/// Input for vault.ssh.port_forward.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultSshPortForwardInput {
    /// Handle URI of an ssh-category Secret.
    pub handle: String,
    /// SSH bastion target in `host:port` form.
    pub target: String,
    /// Local port to bind on `127.0.0.1`.
    pub local_port: u16,
    /// Remote host for the forwarded connection.
    pub remote_host: String,
    /// Remote port for the forwarded connection.
    pub remote_port: u16,
    /// Optional TTL in seconds for the tunnel (agent enforces graceful shutdown).
    pub ttl_secs: Option<u64>,
    /// Operator confirmation (defaults to `true` for Claude Code clients).
    pub operator_confirmation: Option<bool>,
}

/// Input for vault.ssh.shell.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultSshShellInput {
    /// Handle URI of an ssh-category Secret.
    pub handle: String,
    /// SSH target in `host:port` form.
    pub target: String,
}

// ---------------------------------------------------------------------------
// HTTP tool inputs
// ---------------------------------------------------------------------------

/// Input for vault.http.request.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultHttpRequestInput {
    /// Handle URI of a token | password | key category Secret (optional auth).
    pub handle: Option<String>,
    /// HTTP method: GET | POST | PUT | PATCH | DELETE.
    pub method: String,
    /// Target URL.
    pub url: String,
    /// Optional extra request headers as key-value pairs.
    pub headers: Option<HashMap<String, String>>,
    /// Optional request body string.
    pub body: Option<String>,
}

/// Input for vault.http.download.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultHttpDownloadInput {
    /// URL to download from.
    pub url: String,
    /// Absolute destination path on the agent's filesystem.
    pub dest_path: String,
    /// Optional handle URI of an auth credential.
    pub handle: Option<String>,
}

/// Input for vault.http.upload.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultHttpUploadInput {
    /// URL to upload to.
    pub url: String,
    /// Absolute source path on the agent's filesystem.
    pub source_path: String,
    /// Optional handle URI of an auth credential.
    pub handle: Option<String>,
    /// Content-Type header (default: application/octet-stream).
    pub content_type: Option<String>,
}

// ---------------------------------------------------------------------------
// Process spawn input
// ---------------------------------------------------------------------------

/// Input for vault.spawn.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultSpawnInput {
    /// Handles to vault secrets injected as environment variables.
    pub secret_handles: Vec<String>,
    /// Command to run.
    pub command: String,
    /// Optional command arguments.
    pub args: Option<Vec<String>>,
    /// Optional extra environment variables.
    pub env: Option<Vec<(String, String)>>,
    /// Optional working directory for the child process.
    pub working_dir: Option<String>,
}

// ---------------------------------------------------------------------------
// Crypto tool inputs
// ---------------------------------------------------------------------------

/// Input for vault.crypto.sign.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultCryptoSignInput {
    /// Handle URI of a key-category Secret holding the signing key.
    pub handle: String,
    /// Base64-encoded payload to sign.
    pub message_b64: String,
    /// Signing algorithm (default: ed25519).
    pub algorithm: Option<String>,
}

/// Input for vault.crypto.decrypt.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultCryptoDecryptInput {
    /// Handle URI of a key-category Secret holding the decryption key.
    pub handle: String,
    /// Base64-encoded ciphertext (format: `[nonce 24 bytes || ct || tag 16 bytes]`).
    pub ciphertext_b64: String,
    /// Additional associated data, base64-encoded (default: empty).
    pub aad_b64: Option<String>,
}

// ---------------------------------------------------------------------------
// Tool group marker type
// ---------------------------------------------------------------------------

/// Marker struct for the proxy tool group.
pub struct ProxyTools;

impl ProxyTools {
    /// Build a `ToolRouter` containing all proxy tools.
    #[must_use]
    pub fn router() -> ToolRouter<MerkleMcpServer> {
        MerkleMcpServer::proxy_router()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_handle(raw: &str) -> Result<Handle, ErrorData> {
    raw.parse::<Handle>()
        .map_err(|e| ErrorData::invalid_params(format!("invalid handle: {e}"), None))
}

fn resolve_namespace(session: &crate::session::SessionState) -> Result<Uuid, ErrorData> {
    session
        .namespace_id()
        .ok_or_else(crate::errors::namespace_not_bound)
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[expect(
    missing_docs,
    reason = "rmcp proc-macro generates the associated fn; doc lives on the #[tool] description attribute"
)]
#[rmcp::tool_router(router = proxy_router)]
impl MerkleMcpServer {
    /// Execute a remote command over SSH using credentials from an ssh-category
    /// Secret. Exit code, stdout (max 64 KiB), and stderr (max 16 KiB) are
    /// returned. Credentials never appear in the response.
    #[tool(
        name = "vault.ssh.exec",
        description = "Execute a remote command over SSH using credentials from a Secret. Exit code, stdout (max 64 KiB), and stderr (max 16 KiB) are returned. Credentials never appear in the response."
    )]
    pub async fn vault_ssh_exec(
        &self,
        Parameters(input): Parameters<VaultSshExecInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let key_handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        // Build the full command string from command + args.
        let command = if let Some(args) = input.args {
            let mut parts = vec![input.command];
            parts.extend(args);
            parts.join(" ")
        } else {
            input.command
        };

        let resp = self
            .client
            .proxy_ssh_exec(ProxySshExecRequest {
                namespace_id,
                key_handle,
                target: input.target,
                command,
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "exit_code": resp.exit_code,
                "stdout": resp.stdout,
                "stderr": resp.stderr,
            })
            .to_string(),
        )]))
    }

    /// Copy files to or from a remote host using SSH credentials from a Secret.
    /// Direction: `upload` or `download`.
    #[tool(
        name = "vault.ssh.copy",
        description = "Copy files to or from a remote host using SSH credentials from a Secret. Direction: upload or download."
    )]
    pub async fn vault_ssh_copy(
        &self,
        Parameters(input): Parameters<VaultSshCopyInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let key_handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let direction = match input.direction.to_lowercase().as_str() {
            "download" => SshCopyDirection::Download,
            _ => SshCopyDirection::Upload,
        };

        let resp = self
            .client
            .proxy_ssh_copy(ProxySshCopyRequest {
                namespace_id,
                key_handle,
                target: input.target,
                source: input.source,
                dest: input.dest,
                direction,
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "bytes_transferred": resp.bytes_transferred,
                "exit_code": resp.exit_code,
            })
            .to_string(),
        )]))
    }

    /// Establish a local SSH port forward using credentials from a Secret.
    /// Returns `session_id` and `local_addr`.
    #[tool(
        name = "vault.ssh.port_forward",
        description = "Establish a local SSH port forward using credentials from a Secret. Returns session_id and local_addr. The tunnel is torn down on session close or TTL expiry."
    )]
    pub async fn vault_ssh_port_forward(
        &self,
        Parameters(input): Parameters<VaultSshPortForwardInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let key_handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let resp = self
            .client
            .proxy_ssh_port_forward(ProxyPortForwardRequest {
                namespace_id,
                key_handle,
                target: input.target,
                local_port: input.local_port,
                remote_host: input.remote_host,
                remote_port: input.remote_port,
                ttl_secs: input.ttl_secs,
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "session_id": resp.session_id.to_string(),
                "local_addr": resp.local_addr,
            })
            .to_string(),
        )]))
    }

    /// Open a buffered SSH shell session. Full PTY streaming is not yet
    /// implemented; this tool returns a `vault.not_implemented` error.
    /// Use `vault.ssh.exec` for non-interactive commands.
    #[tool(
        name = "vault.ssh.shell",
        description = "Open an interactive SSH shell session. NOT YET IMPLEMENTED — the server returns 501. Use vault.ssh.exec for non-interactive commands."
    )]
    pub async fn vault_ssh_shell(
        &self,
        Parameters(input): Parameters<VaultSshShellInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let key_handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        // The server returns 501; we forward the call and let the error mapper
        // translate it to vault.not_implemented.
        self.client
            .proxy_ssh_shell(ProxySshShellRequest {
                namespace_id,
                key_handle,
                target: input.target,
            })
            .await
            .map_err(|e| {
                // 501 → explicit not_implemented message; other errors mapped normally.
                use merkle_companion_client::ClientError;
                if let ClientError::Http { status: 501, .. } = &e {
                    crate::errors::not_implemented("vault.ssh.shell")
                } else {
                    client_error_to_mcp(e)
                }
            })?;

        // Unreachable in practice (server always returns 501 today), but
        // keeps the return type consistent.
        Err(crate::errors::not_implemented("vault.ssh.shell"))
    }

    /// Perform an HTTP request injecting credentials from a Secret.
    /// Response body is capped at 256 KiB.
    #[tool(
        name = "vault.http.request",
        description = "Perform an HTTP request, optionally injecting credentials from a Secret. Response body is capped at 256 KiB."
    )]
    pub async fn vault_http_request(
        &self,
        Parameters(input): Parameters<VaultHttpRequestInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let secret_handle = input.handle.as_deref().map(parse_handle).transpose()?;

        let headers: Vec<(String, String)> =
            input.headers.unwrap_or_default().into_iter().collect();

        let resp = self
            .client
            .proxy_http_request(ProxyHttpRequestRequest {
                namespace_id,
                secret_handle,
                spec: HttpRequestSpecDto {
                    method: input.method,
                    url: input.url,
                    headers,
                    body: input.body,
                },
                auth: None,
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "status": resp.status,
                "body": resp.body,
                "headers": resp.headers,
            })
            .to_string(),
        )]))
    }

    /// Download a file to the agent filesystem, optionally using credentials
    /// from a Secret for authentication.
    #[tool(
        name = "vault.http.download",
        description = "Download a file to the agent filesystem, optionally using credentials from a Secret for authentication."
    )]
    pub async fn vault_http_download(
        &self,
        Parameters(input): Parameters<VaultHttpDownloadInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let secret_handle = input.handle.as_deref().map(parse_handle).transpose()?;

        let resp = self
            .client
            .proxy_http_download(ProxyHttpDownloadRequest {
                namespace_id,
                secret_handle,
                url: input.url,
                dest_path: input.dest_path.clone(),
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "status": resp.status,
                "bytes": resp.bytes,
                "content_type": resp.content_type,
                "dest_path": input.dest_path,
            })
            .to_string(),
        )]))
    }

    /// Upload a local file from the agent filesystem to a URL, optionally
    /// using credentials from a Secret.
    #[tool(
        name = "vault.http.upload",
        description = "Upload a file from the agent filesystem to a URL, optionally using credentials from a Secret for authentication."
    )]
    pub async fn vault_http_upload(
        &self,
        Parameters(input): Parameters<VaultHttpUploadInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let secret_handle = input.handle.as_deref().map(parse_handle).transpose()?;

        let resp = self
            .client
            .proxy_http_upload(ProxyHttpUploadRequest {
                namespace_id,
                secret_handle,
                url: input.url,
                source_path: input.source_path,
                content_type: input.content_type,
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "status": resp.status,
                "bytes_sent": resp.bytes_sent,
            })
            .to_string(),
        )]))
    }

    /// Spawn a child process on the agent host with vault secrets injected as
    /// environment variables. stdin is closed. stdout/stderr returned.
    /// Credentials never appear in the response.
    #[tool(
        name = "vault.spawn",
        description = "Spawn a child process on the agent host with Secrets injected as environment variables. stdin is closed. stdout/stderr returned. Credentials never appear in the response."
    )]
    pub async fn vault_spawn(
        &self,
        Parameters(input): Parameters<VaultSpawnInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let secret_handles: Result<Vec<Handle>, ErrorData> = input
            .secret_handles
            .iter()
            .map(|h| parse_handle(h))
            .collect();

        let resp = self
            .client
            .proxy_spawn(ProxySpawnRequest {
                namespace_id,
                secret_handles: secret_handles?,
                command: input.command,
                args: input.args.unwrap_or_default(),
                env: input.env.unwrap_or_default(),
                working_dir: input.working_dir,
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "exit_code": resp.exit_code,
                "stdout": resp.stdout,
                "stderr": resp.stderr,
            })
            .to_string(),
        )]))
    }

    /// Sign a payload using a private key stored in a Secret. Returns a
    /// base64-encoded signature. The private key never appears in the response.
    #[tool(
        name = "vault.crypto.sign",
        description = "Sign a payload using a private key stored in a Secret. Returns a base64-encoded signature. The private key never appears in the response."
    )]
    pub async fn vault_crypto_sign(
        &self,
        Parameters(input): Parameters<VaultCryptoSignInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let key_handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let algorithm = input
            .algorithm
            .map(|a| match a.to_lowercase().as_str() {
                "rsa-sha256" | "rsa_sha256" => {
                    merkle_companion_client::dto::CryptoSignAlgorithm::RsaSha256
                }
                _ => merkle_companion_client::dto::CryptoSignAlgorithm::Ed25519,
            })
            .unwrap_or_default();

        let resp = self
            .client
            .proxy_crypto_sign(ProxyCryptoSignRequest {
                namespace_id,
                key_handle,
                message_b64: input.message_b64,
                algorithm,
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "signature_b64": resp.signature_b64,
                "algorithm": resp.algorithm,
            })
            .to_string(),
        )]))
    }

    /// Decrypt a ciphertext using a key stored in a Secret. Returns
    /// base64-encoded plaintext. The private key never appears in the response.
    #[tool(
        name = "vault.crypto.decrypt",
        description = "Decrypt a ciphertext using a key stored in a Secret. Returns base64-encoded plaintext. The private key never appears in the response."
    )]
    pub async fn vault_crypto_decrypt(
        &self,
        Parameters(input): Parameters<VaultCryptoDecryptInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let key_handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        // Validate the ciphertext base64 at the adapter level for fast feedback.
        let _ = base64::engine::general_purpose::STANDARD
            .decode(&input.ciphertext_b64)
            .map_err(|e| ErrorData::invalid_params(format!("ciphertext_b64: {e}"), None))?;

        let resp = self
            .client
            .proxy_crypto_decrypt(ProxyCryptoDecryptRequest {
                namespace_id,
                key_handle,
                ciphertext_b64: input.ciphertext_b64,
                aad_b64: input.aad_b64.unwrap_or_default(),
                algorithm: merkle_companion_client::dto::CryptoDecryptAlgorithm::default(),
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "plaintext_b64": resp.plaintext_b64,
            })
            .to_string(),
        )]))
    }
}
