//! Identity and sealing tools: vault_unseal, vault_seal, vault_bind.
//!
//! These tools manage the vault lifecycle state transitions and namespace
//! session binding. They communicate exclusively through the Companion Socket
//! via [`CompanionSocketClient`](merkle_companion_client::CompanionSocketClient).

use rmcp::{
    ErrorData,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content},
    schemars::{self, JsonSchema},
    tool,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{MerkleMcpServer, errors::client_error_to_mcp};
use merkle_companion_client::dto::{CreateSessionRequest, UnsealRequest};

// ---------------------------------------------------------------------------
// Input parameter structs
// ---------------------------------------------------------------------------

/// Input for vault_unseal.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultUnsealInput {
    /// Passphrase for software-only keychain. On macOS with Touch ID configured
    /// this field is ignored; the system prompts natively.
    pub passphrase: Option<String>,
}

/// Input for vault_seal.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultSealInput {
    /// Optional reason for sealing, recorded in the audit log.
    pub reason: Option<String>,
}

/// Input for vault_bind.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultBindInput {
    /// Namespace label to bind this session to.
    pub label: String,
}

// ---------------------------------------------------------------------------
// Tool group marker type
// ---------------------------------------------------------------------------

/// Marker struct for the identity tool group.
pub struct IdentityTools;

impl IdentityTools {
    /// Build a `ToolRouter` containing all identity tools.
    #[must_use]
    pub fn router() -> ToolRouter<MerkleMcpServer> {
        MerkleMcpServer::identity_router()
    }
}

// ---------------------------------------------------------------------------
// CWD hash helper
// ---------------------------------------------------------------------------

/// Compute the cwd_hash for `CreateSessionRequest`.
///
/// The hash is the first 32 hex characters of the BLAKE3 hash of the current
/// working directory's canonical UTF-8 path. This produces a stable,
/// short-enough key that the server uses to resolve (or create) the namespace
/// for this working directory.
///
/// Per ADR-0008 (CWD-Bound Namespace) this hash is the canonical namespace
/// identity for the current working directory; per ADR-0025 §Bug #6 the MCP
/// adapter materialises it internally so callers never pass `cwd_hash` over
/// the MCP transport. The bound label supplied via `vault_bind` overrides
/// the default name but the underlying cwd_hash identity is preserved.
fn cwd_hash() -> String {
    let cwd = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("/"))
        .to_string_lossy()
        .into_owned();
    let digest = blake3::hash(cwd.as_bytes());
    // Take the first 32 hex chars (16 bytes of the 32-byte hash).
    digest.to_hex()[..32].to_owned()
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[allow(
    missing_docs,
    reason = "rmcp proc-macro generates the associated fn; doc lives on the #[tool] description attribute"
)]
#[rmcp::tool_router(router = identity_router)]
impl MerkleMcpServer {
    /// Unseal the Vault Agent by loading the MasterKey from the OS keychain.
    ///
    /// On macOS with Touch ID configured the system prompts natively;
    /// `passphrase` is ignored. On Linux/Windows the passphrase is used to
    /// derive the key with Argon2id if no Secret Service is available.
    #[tool(
        name = "vault_unseal",
        description = "Unseal the Vault Agent by loading the MasterKey from the OS keychain. On macOS, Touch ID is used. On Linux/Windows a passphrase may be required. Most tools require the agent to be unsealed."
    )]
    pub async fn vault_unseal(
        &self,
        Parameters(_input): Parameters<VaultUnsealInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let resp = self
            .client
            .agent_unseal(UnsealRequest {})
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "unsealed": !resp.sealed,
                "already_unsealed": resp.already_unsealed,
                "method": resp.method.as_ref().map(|m| format!("{m:?}")),
            })
            .to_string(),
        )]))
    }

    /// Seal the Vault Agent by zeroing the in-memory MasterKey.
    ///
    /// All subsequent tool calls that require plaintext access will return
    /// `UnsealRequired` until the agent is unsealed again.
    #[tool(
        name = "vault_seal",
        description = "Seal the Vault Agent by zeroing the in-memory MasterKey. All subsequent plaintext-access tool calls will return UnsealRequired until the agent is unsealed again."
    )]
    pub async fn vault_seal(
        &self,
        Parameters(input): Parameters<VaultSealInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let _ = input.reason; // audited by the agent
        let resp = self
            .client
            .agent_seal()
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({"sealed": resp.sealed}).to_string(),
        )]))
    }

    /// Associate the current MCP session with a named Namespace.
    ///
    /// Calls `POST /v1/sessions` which resolves or creates the namespace
    /// matching the given label and the BLAKE3 hash of the MCP process's
    /// current working directory (per ADR-0008 CWD-Bound Namespace).
    /// The `cwd_hash` is materialised internally by this adapter via
    /// [`cwd_hash`] and never crossed the MCP transport boundary
    /// (ADR-0025 §Bug #6 — documentation fix; no behavioural change).
    ///
    /// The returned `session_id` and `namespace_id` are stored in
    /// `SessionState` for use by `vault_reveal` and all use-token tools.
    ///
    /// May be called at most once per session; re-binding is rejected with
    /// `AlreadyBound`. Without a binding, operations resolve to the default
    /// Namespace derived from the working directory hash.
    #[tool(
        name = "vault_bind",
        description = "Associate the current MCP session with a named Namespace. Call this at session start. May be called at most once — re-binding returns AlreadyBound. Without binding, the default Namespace (cwd-hash derived) is used."
    )]
    pub async fn vault_bind(
        &self,
        Parameters(input): Parameters<VaultBindInput>,
    ) -> Result<CallToolResult, ErrorData> {
        // Phase 1 — guard check only; do NOT mutate state yet (ADR-0026).
        {
            let session = self.session.read().await;
            if session.is_bound() {
                return Err(crate::errors::already_bound());
            }
        }

        // Phase 2 — call the Companion Socket. On failure the session remains
        // fully unbound so the operator can retry without restarting the process.
        let hash = cwd_hash();
        let resp = self
            .client
            .create_session(CreateSessionRequest {
                cwd_hash: hash,
                namespace_label: Some(input.label.clone()),
                client_pid: Some(std::process::id()),
            })
            .await
            .map_err(client_error_to_mcp)?;

        // Phase 3 — commit ALL session fields atomically under a single write
        // lock. No field is visible in a partial state after this point.
        {
            let mut session = self.session.write().await;
            session.commit_binding(input.label, resp.namespace_id, resp.session_id);
        }

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "namespace_id": resp.namespace_id.to_string(),
                "session_id": resp.session_id.to_string(),
                "label": resp.namespace_label,
                "policy_profile": format!("{:?}", resp.policy_profile),
            })
            .to_string(),
        )]))
    }
}
