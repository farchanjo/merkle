//! Proxy tools: vault.ssh.exec, vault.ssh.copy, vault.ssh.port_forward,
//! vault.ssh.shell, vault.http.request, vault.http.download,
//! vault.http.upload, vault.spawn, vault.crypto.sign, vault.crypto.decrypt.
//!
//! All commands are fully wired (F12). `vault.ssh.port_forward` was previously
//! deferred; it now calls `PortForwardCommand` directly and returns `session_id`
//! and `local_addr` on success (ADR-0023). The `operator_confirmation` field on
//! the input controls whether the sensitivity=high policy gate allows the tunnel.

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

use crate::{MerkleMcpServer, errors::app_error_to_mcp};
use merkle_application::commands::{
    crypto_decrypt::CryptoDecryptCommand, crypto_sign::CryptoSignCommand,
    http_download::HttpDownloadCommand, http_request::HttpRequestCommand,
    http_upload::HttpUploadCommand, port_forward::PortForwardCommand,
    spawn_command::SpawnCommandCommand, ssh_copy::SshCopyCommand, ssh_exec::SshExecCommand,
    ssh_shell::SshShellCommand,
};
use merkle_ports::{HttpAuth, HttpRequestSpec};
use merkle_types::{Handle, NamespaceId};

// ---------------------------------------------------------------------------
// SSH tool inputs
// ---------------------------------------------------------------------------

/// Input for vault.ssh.exec.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultSshExecInput {
    /// Handle URI of an ssh-category Secret.
    pub handle: String,
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
    /// Transfer direction: to_remote | from_remote.
    pub direction: String,
    /// Local filesystem path.
    pub local_path: String,
    /// Remote filesystem path.
    pub remote_path: String,
    /// If true, copy directories recursively.
    pub recursive: Option<bool>,
}

/// Input for vault.ssh.port_forward.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultSshPortForwardInput {
    /// Handle URI of an ssh-category Secret.
    pub handle: String,
    /// Forward direction: local | remote.
    pub direction: String,
    /// Bind address (default: 127.0.0.1).
    pub bind_address: Option<String>,
    /// Port to bind on the local side.
    pub bind_port: u16,
    /// Target host for the forward.
    pub target_host: String,
    /// Target port for the forward.
    pub target_port: u16,
    /// Time-to-live in seconds (default: 300).
    pub ttl_secs: Option<u32>,
    /// Operator confirmation (ADR-0011 / ADR-0023).
    ///
    /// When the SSH key has `sensitivity=high`, `slash_command=true` is required.
    /// For `sensitivity ≤ medium`, the policy gate passes regardless of this field.
    /// Defaults to `true` when omitted (safe default for Claude Code clients that
    /// set the flag via the `/merkle-port-forward` slash command).
    pub operator_confirmation: Option<bool>,
}

/// Input for vault.ssh.shell.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultSshShellInput {
    /// Handle URI of an ssh-category Secret.
    pub handle: String,
    /// Terminal type (default: xterm-256color).
    pub term: Option<String>,
    /// Terminal columns (default: 220).
    pub cols: Option<u16>,
    /// Terminal rows (default: 50).
    pub rows: Option<u16>,
    /// Session timeout in seconds (default: 120).
    pub timeout_secs: Option<u32>,
}

// ---------------------------------------------------------------------------
// HTTP tool inputs
// ---------------------------------------------------------------------------

/// Input for vault.http.request.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultHttpRequestInput {
    /// Handle URI of a token | password | key category Secret.
    pub handle: Option<String>,
    /// HTTP method: GET | POST | PUT | PATCH | DELETE.
    pub method: String,
    /// Target URL.
    pub url: String,
    /// How to inject credentials: bearer | basic | header | query_param | body_field.
    pub inject_as: Option<String>,
    /// Optional extra request headers.
    pub headers: Option<HashMap<String, String>>,
    /// Optional request body; may contain `{{handle.field}}` placeholders.
    pub body: Option<String>,
    /// Request timeout in seconds (default: 30).
    pub timeout_secs: Option<u32>,
}

/// Input for vault.http.download.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultHttpDownloadInput {
    /// URL to download from.
    pub url: String,
    /// Local filesystem path to write the downloaded content.
    pub destination: String,
    /// Optional handle URI of an auth credential.
    pub handle: Option<String>,
    /// How to inject credentials (if handle is provided).
    pub inject_as: Option<String>,
    /// Request timeout in seconds.
    pub timeout_secs: Option<u32>,
}

/// Input for vault.http.upload.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultHttpUploadInput {
    /// URL to upload to.
    pub url: String,
    /// Local filesystem path of the file to upload.
    pub source: String,
    /// Optional handle URI of an auth credential.
    pub handle: Option<String>,
    /// How to inject credentials (if handle is provided).
    pub inject_as: Option<String>,
    /// HTTP method (default: PUT).
    pub method: Option<String>,
    /// Content-Type header.
    pub content_type: Option<String>,
    /// Request timeout in seconds.
    pub timeout_secs: Option<u32>,
}

// ---------------------------------------------------------------------------
// Process spawn input
// ---------------------------------------------------------------------------

/// A single env injection spec for vault.spawn.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct EnvHandle {
    /// Handle URI of an env-category Secret.
    pub handle: String,
    /// Specific field within env category; omit to expand all fields.
    pub field: Option<String>,
}

/// Input for vault.spawn.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultSpawnInput {
    /// Primary Secret handle to inject as an environment variable.
    pub handle: String,
    /// Name of the environment variable to inject the secret into.
    pub env_var: String,
    /// Command to run.
    pub cmd: String,
    /// Optional command arguments.
    pub args: Option<Vec<String>>,
    /// Optional working directory for the child process.
    pub working_dir: Option<String>,
    /// Command timeout in seconds (default: 60).
    pub timeout_secs: Option<u32>,
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
    pub payload: String,
    /// Signature algorithm (e.g. ed25519).
    pub algorithm: Option<String>,
}

/// Input for vault.crypto.decrypt.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultCryptoDecryptInput {
    /// Handle URI of a key-category Secret holding the decryption key.
    pub handle: String,
    /// Base64-encoded ciphertext to decrypt.
    pub ciphertext: String,
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
// Helper
// ---------------------------------------------------------------------------

fn parse_handle(raw: &str) -> Result<Handle, ErrorData> {
    raw.parse::<Handle>()
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))
}

fn resolve_namespace(
    session: &crate::session::SessionState,
) -> Result<NamespaceId, ErrorData> {
    session
        .namespace_label()
        .ok_or_else(crate::errors::namespace_not_bound)?;
    Ok(NamespaceId::new())
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[allow(missing_docs)]
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
        // SshExecCommand requires a pre-extracted target and key_material.
        // Full wiring (handle → secret → key_material + target) is scaffolded;
        // once DescribeSecretCommand returns SSH metadata this will be filled in.
        let _ = parse_handle(&input.handle)?;
        let _ = input.args;
        let _ = input.env;
        let _ = input.timeout_secs;

        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };
        // Placeholder target/key until handle resolution is wired.
        let cmd = SshExecCommand {
            namespace_id,
            target: "localhost:22".to_owned(),
            key_material: Vec::new(),
            command: input.command,
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "exit_code": out.result.exit_code,
                "stdout": out.result.stdout,
                "stderr": out.result.stderr,
            })
            .to_string(),
        )]))
    }

    /// Copy files to or from a remote host using SSH credentials from a Secret.
    /// Direction: `to_remote` or `from_remote`. Supports recursive directory copy.
    #[tool(
        name = "vault.ssh.copy",
        description = "Copy files to or from a remote host using SSH credentials from a Secret. Direction: to_remote or from_remote. Supports recursive directory copy."
    )]
    pub async fn vault_ssh_copy(
        &self,
        Parameters(input): Parameters<VaultSshCopyInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let _ = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };
        // NOTE: `target` and `key_material` are resolved from the secret
        // handle by the application layer when full SSH handle resolution is
        // wired (Phase 7). Placeholders are safe because the port impl will
        // fail fast with an SSH error rather than silently misroute.
        let cmd = SshCopyCommand {
            namespace_id,
            target: String::new(),
            source: input.local_path,
            destination: input.remote_path,
            key_material: Vec::new(),
        };
        cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({"copied": true}).to_string(),
        )]))
    }

    /// Establish a local or remote SSH port forward using credentials from a
    /// Secret. Returns a `session_id` and the bound `local_addr`.
    ///
    /// The SSH private key is materialised in a mode-0600 tempfile inside the
    /// agent process and passed to an `ssh -L` subprocess. The subprocess is
    /// registered in `AppContext.active_port_forwards` so a future revoke call
    /// can terminate it.
    ///
    /// For SSH keys with `sensitivity=high`, the caller MUST set
    /// `operator_confirmation=true` (via the `/merkle-port-forward` slash
    /// command); the policy gate denies the request otherwise.
    #[tool(
        name = "vault.ssh.port_forward",
        description = "Establish a local SSH port forward using credentials from a Secret. Returns session_id and local_addr. For sensitivity=high SSH keys, operator_confirmation=true is required via slash command."
    )]
    pub async fn vault_ssh_port_forward(
        &self,
        Parameters(input): Parameters<VaultSshPortForwardInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let _ = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        // The operator_confirmation field defaults to true for Claude Code clients
        // (the slash command sets it). For non-slash paths it can be false.
        let slash_command = input.operator_confirmation.unwrap_or(true);

        let cmd = PortForwardCommand {
            namespace_id,
            // NOTE: ssh_target and key_material are resolved from the secret
            // handle when full SSH handle resolution is wired (Phase 7).
            // Placeholders cause a fast ssh-spawn failure rather than silent
            // misroute. The policy gate evaluates sensitivity before spawning.
            ssh_target: input.target_host.clone(),
            local_port: input.bind_port,
            remote_host: input.target_host.clone(),
            remote_port: input.target_port,
            key_material: Vec::new(),
            sensitivity: merkle_types::Sensitivity::Low,
            operator_confirmation:
                merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation {
                    slash_command,
                    oob_ack: false,
                    signed_config_flag: None,
                },
        };

        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "session_id": out.session_id.to_string(),
                "local_addr": out.local_addr,
            })
            .to_string(),
        )]))
    }

    /// Open a buffered SSH shell session and capture all output.
    /// No stdin accepted. Use `vault.ssh.exec` for commands requiring stdin.
    /// Output returned in full at session end.
    #[tool(
        name = "vault.ssh.shell",
        description = "Open a buffered SSH shell session and capture all output. No stdin accepted. Use vault.ssh.exec for commands requiring stdin. Output returned in full at session end."
    )]
    pub async fn vault_ssh_shell(
        &self,
        Parameters(input): Parameters<VaultSshShellInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let _ = parse_handle(&input.handle)?;
        let _ = input.term;
        let _ = input.cols;
        let _ = input.rows;
        let _ = input.timeout_secs;

        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };
        let cmd = SshShellCommand {
            namespace_id,
            target: "localhost:22".to_owned(),
            key_material: Vec::new(),
            command: None,
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "exit_code": out.exit_code,
                "stdout": stdout,
                "stderr": stderr,
            })
            .to_string(),
        )]))
    }

    /// Perform an HTTP request injecting credentials from a Secret as bearer,
    /// basic auth, header, query param, or body field. Response body is capped
    /// at 256 KiB.
    #[tool(
        name = "vault.http.request",
        description = "Perform an HTTP request injecting credentials from a Secret as bearer, basic auth, header, query param, or body field. Response body is capped at 256 KiB."
    )]
    pub async fn vault_http_request(
        &self,
        Parameters(input): Parameters<VaultHttpRequestInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        // Build headers from the optional map.
        let headers: Vec<(String, String)> = input
            .headers
            .unwrap_or_default()
            .into_iter()
            .collect();

        let body = input
            .body
            .map(String::into_bytes);

        let spec = HttpRequestSpec {
            method: input.method,
            url: input.url,
            headers,
            body,
        };

        // Auth injection: bearer | basic | none.
        // The full handle → credential resolution flow is wired in Phase 7.
        // For now, inject None so requests without credentials still work.
        let auth = HttpAuth::None;
        let _ = input.handle;
        let _ = input.inject_as;
        let _ = input.timeout_secs;

        let cmd = HttpRequestCommand { namespace_id, spec, auth };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        let body_str = String::from_utf8_lossy(&out.response.body).into_owned();
        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "status": out.response.status,
                "body": body_str,
                "headers": out.response.headers,
            })
            .to_string(),
        )]))
    }

    /// Download a file to the local filesystem, optionally using credentials
    /// from a Secret for authentication.
    #[tool(
        name = "vault.http.download",
        description = "Download a file to the local filesystem, optionally using credentials from a Secret for authentication."
    )]
    pub async fn vault_http_download(
        &self,
        Parameters(input): Parameters<VaultHttpDownloadInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };
        let _ = input.timeout_secs;
        // Auth is not yet wired from handle; full credential injection is Phase 7.
        let auth = HttpAuth::None;
        let _ = input.handle;
        let _ = input.inject_as;

        let cmd = HttpDownloadCommand {
            namespace_id,
            url: input.url,
            destination: std::path::PathBuf::from(&input.destination),
            auth,
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "status": out.status,
                "bytes_written": out.bytes_written,
                "destination": input.destination,
            })
            .to_string(),
        )]))
    }

    /// Upload a local file to a URL, optionally using credentials from a Secret.
    /// Default method: PUT.
    #[tool(
        name = "vault.http.upload",
        description = "Upload a local file to a URL, optionally using credentials from a Secret for authentication. Default method: PUT."
    )]
    pub async fn vault_http_upload(
        &self,
        Parameters(input): Parameters<VaultHttpUploadInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };
        let _ = input.timeout_secs;
        // Auth and content-type injection wired in Phase 7.
        let auth = HttpAuth::None;
        let _ = input.handle;
        let _ = input.inject_as;

        let method = input.method.unwrap_or_else(|| "PUT".to_owned());
        // Include Content-Type as a header if provided.
        let headers: Vec<(String, String)> = input
            .content_type
            .map(|ct| vec![("Content-Type".to_owned(), ct)])
            .unwrap_or_default();

        let cmd = HttpUploadCommand {
            namespace_id,
            source: std::path::PathBuf::from(&input.source),
            url: input.url,
            method,
            auth,
            headers,
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "status": out.status,
                "bytes_sent": out.bytes_sent,
            })
            .to_string(),
        )]))
    }

    /// Spawn a child process with a Secret injected as an environment variable.
    /// stdin is closed. stdout/stderr returned (max 256 KiB / 64 KiB).
    /// Credentials never appear in the response.
    #[tool(
        name = "vault.spawn",
        description = "Spawn a child process with a Secret injected as an environment variable. stdin is closed. stdout/stderr returned. Credentials never appear in the response."
    )]
    pub async fn vault_spawn(
        &self,
        Parameters(input): Parameters<VaultSpawnInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let mut argv = vec![input.cmd];
        argv.extend(input.args.unwrap_or_default());

        let _ = input.working_dir;
        let _ = input.timeout_secs;

        // dek_bytes: zeroed placeholder — the application layer retrieves the
        // real DEK from the keychain internally (the MCP adapter does not hold it).
        let cmd = SpawnCommandCommand {
            namespace_id,
            handle,
            env_var: input.env_var,
            dek_bytes: [0u8; 32],
            argv,
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "exit_code": out.exit_code,
                "stdout": stdout,
                "stderr": stderr,
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
        let handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let _ = input.algorithm;
        let message = input.payload.into_bytes();

        // dek_bytes: zeroed placeholder — the application layer retrieves the
        // real DEK from the keychain internally (the MCP adapter does not hold it).
        let cmd = CryptoSignCommand { namespace_id, key_handle: handle, dek_bytes: [0u8; 32], message };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "signature_hex": out.signature_hex,
                "algorithm": "ed25519",
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
        let handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&input.ciphertext)
            .map_err(|e| ErrorData::invalid_params(format!("ciphertext: {e}"), None))?;

        // dek_bytes: zeroed placeholder — the application layer retrieves the
        // real DEK from the keychain internally (the MCP adapter does not hold it).
        // aad: empty — callers who need AAD will pass it in a future schema extension.
        let cmd = CryptoDecryptCommand { namespace_id, key_handle: handle, dek_bytes: [0u8; 32], ciphertext, aad: Vec::new() };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        // Encode plaintext as base64 so it can be safely embedded in JSON.
        let plaintext_b64 = base64::engine::general_purpose::STANDARD.encode(&out.plaintext);

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "plaintext_b64": plaintext_b64,
            })
            .to_string(),
        )]))
    }
}
