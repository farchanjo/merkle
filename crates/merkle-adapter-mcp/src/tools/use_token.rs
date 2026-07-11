//! Use Token and Tempfile tools:
//! vault_use, vault_write_tempfile, vault_write_fifo, vault_revoke_tempfile.
//!
//! All four tools forward to the Companion Socket endpoints added in PR3.
//! The session_id from `vault_bind` is required for token issuance and
//! is read from the per-session [`SessionState`].

use rmcp::{
    ErrorData,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content},
    schemars::{self, JsonSchema},
    tool,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{MerkleMcpServer, errors::client_error_to_mcp};
use merkle_companion_client::dto::{UseTokenRequest, WriteFifoRequest, WriteTempfileRequest};
use merkle_types::Handle;

// ---------------------------------------------------------------------------
// Input parameter structs
// ---------------------------------------------------------------------------

/// Input for vault_use.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultUseInput {
    /// Handle URI of the Secret to issue a token for.
    pub handle: String,
    /// Human-readable reason recorded in the audit log.
    pub purpose: String,
}

/// Input for vault_write_tempfile.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultWriteTempfileInput {
    /// Handle URI of the Secret to materialise.
    pub handle: String,
    /// Octal permission mode string (default: "0600"). Informational only —
    /// the agent always writes mode 0600.
    pub mode: Option<String>,
}

/// Input for vault_write_fifo.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultWriteFifoInput {
    /// Handle URI of the Secret to materialise as a FIFO.
    pub handle: String,
}

/// Input for vault_revoke_tempfile.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultRevokeTempfileInput {
    /// Opaque token previously returned by vault_write_tempfile or vault_write_fifo.
    pub path: String,
}

// ---------------------------------------------------------------------------
// Tool group marker type
// ---------------------------------------------------------------------------

/// Marker struct for the use_token tool group.
pub struct UseTokenTools;

impl UseTokenTools {
    /// Build a `ToolRouter` containing all use-token tools.
    #[must_use]
    pub fn router() -> ToolRouter<MerkleMcpServer> {
        MerkleMcpServer::use_token_router()
    }
}

// ---------------------------------------------------------------------------
// Session resolution helpers
// ---------------------------------------------------------------------------

fn resolve_namespace_id(session: &crate::session::SessionState) -> Result<Uuid, ErrorData> {
    session
        .namespace_id()
        .ok_or_else(crate::errors::namespace_not_bound)
}

fn resolve_session_id(session: &crate::session::SessionState) -> Result<Uuid, ErrorData> {
    session
        .session_id()
        .ok_or_else(crate::errors::namespace_not_bound)
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[allow(
    missing_docs,
    reason = "rmcp proc-macro generates the associated fn; doc lives on the #[tool] description attribute"
)]
#[rmcp::tool_router(router = use_token_router)]
impl MerkleMcpServer {
    /// Issue a short-lived Use Token for a Secret. The plaintext never appears
    /// in the MCP response. Pass the `use_token` to `vault_ssh_exec` or another
    /// proxy tool. Default TTL: 60 seconds.
    #[tool(
        name = "vault_use",
        description = "Issue a short-lived Use Token for a Secret. The plaintext never appears in the response. Pass the use_token to vault_ssh_exec or another proxy tool. Default TTL: 60 seconds."
    )]
    pub async fn vault_use(
        &self,
        Parameters(input): Parameters<VaultUseInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = input
            .handle
            .parse::<Handle>()
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        let (namespace_id, session_id) = {
            let session = self.session.read().await;
            let ns = resolve_namespace_id(&session)?;
            let sid = resolve_session_id(&session)?;
            (ns, sid)
        };

        let _ = input.purpose;

        let resp = self
            .client
            .mint_use_token(UseTokenRequest {
                namespace_id,
                handle,
                session_id,
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "use_token": resp.use_token,
                "expires_at": resp.expires_at.to_rfc3339(),
            })
            .to_string(),
        )]))
    }

    /// Materialise a Secret on the local filesystem as a Tempfile.
    /// Cleaned up on session close or idle timeout.
    /// Useful for tools that require a file path (e.g. `ssh -i`).
    #[tool(
        name = "vault_write_tempfile",
        description = "Materialise a Secret on the local filesystem as a 0600 Tempfile. Cleaned up on session close. Useful for tools that require a file path, e.g. ssh -i."
    )]
    pub async fn vault_write_tempfile(
        &self,
        Parameters(input): Parameters<VaultWriteTempfileInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = input
            .handle
            .parse::<Handle>()
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        let (namespace_id, session_id) = {
            let session = self.session.read().await;
            let ns = resolve_namespace_id(&session)?;
            let sid = resolve_session_id(&session)?;
            (ns, sid)
        };

        let _ = input.mode; // agent always uses 0600

        // Mint the single-use authorization token the agent now requires before
        // it will materialize any plaintext, then consume it on the same call.
        let mint = self
            .client
            .mint_use_token(UseTokenRequest {
                namespace_id,
                handle: handle.clone(),
                session_id,
            })
            .await
            .map_err(client_error_to_mcp)?;

        let resp = self
            .client
            .write_tempfile(WriteTempfileRequest {
                namespace_id,
                handle,
                session_id,
                use_token: mint.use_token,
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "opaque_token": resp.opaque_token,
                "expires_at": resp.expires_at.to_rfc3339(),
            })
            .to_string(),
        )]))
    }

    /// Materialise a Secret as a named pipe (FIFO). The agent writes the
    /// plaintext once; the file is removed after the first successful read.
    /// Suitable for programs that open a credential path exactly once.
    #[tool(
        name = "vault_write_fifo",
        description = "Materialise a Secret as a named pipe (FIFO). The agent writes the plaintext once; removed after the first read. Suitable for programs that open a credential path exactly once."
    )]
    pub async fn vault_write_fifo(
        &self,
        Parameters(input): Parameters<VaultWriteFifoInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = input
            .handle
            .parse::<Handle>()
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        let (namespace_id, session_id) = {
            let session = self.session.read().await;
            let ns = resolve_namespace_id(&session)?;
            let sid = resolve_session_id(&session)?;
            (ns, sid)
        };

        // Mint the single-use authorization token the agent now requires before
        // it will create the FIFO or write any plaintext, then consume it here.
        let mint = self
            .client
            .mint_use_token(UseTokenRequest {
                namespace_id,
                handle: handle.clone(),
                session_id,
            })
            .await
            .map_err(client_error_to_mcp)?;

        let resp = self
            .client
            .write_fifo(WriteFifoRequest {
                namespace_id,
                handle,
                session_id,
                use_token: mint.use_token,
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "opaque_token": resp.opaque_token,
                "expires_at": resp.expires_at.to_rfc3339(),
            })
            .to_string(),
        )]))
    }

    /// Explicitly revoke a Tempfile or FIFO before session close.
    /// The file is removed immediately and the path becomes invalid.
    #[tool(
        name = "vault_revoke_tempfile",
        description = "Explicitly revoke a Tempfile or FIFO before session close or idle timeout. The file is removed immediately."
    )]
    pub async fn vault_revoke_tempfile(
        &self,
        Parameters(input): Parameters<VaultRevokeTempfileInput>,
    ) -> Result<CallToolResult, ErrorData> {
        // Ensure a session is active (namespace must be bound).
        {
            let session = self.session.read().await;
            let _ = resolve_namespace_id(&session)?;
        }

        let resp = self
            .client
            .revoke_tempfile(&input.path)
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({"revoked": resp.revoked}).to_string(),
        )]))
    }
}
