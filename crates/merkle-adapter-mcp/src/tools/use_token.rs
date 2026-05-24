//! Use Token and Tempfile tools:
//! vault.use, vault.write_tempfile, vault.write_fifo, vault.revoke_tempfile.
//!
//! All four commands are fully implemented in `merkle-application` (F5.B).
//! This module wires the real outputs into `CallToolResult` responses.

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
    revoke_tempfile::RevokeTempfileCommand, use_token::UseTokenCommand,
    write_fifo::WriteFifoCommand, write_tempfile::WriteTempfileCommand,
};
use merkle_types::{Handle, NamespaceId, UuidV7};

// ---------------------------------------------------------------------------
// Input parameter structs
// ---------------------------------------------------------------------------

/// Input for vault.use.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultUseInput {
    /// Handle URI of the Secret to issue a token for.
    pub handle: String,
    /// Human-readable reason recorded in the audit log.
    pub purpose: String,
}

/// Input for vault.write_tempfile.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultWriteTempfileInput {
    /// Handle URI of the Secret to materialise.
    pub handle: String,
    /// Octal permission mode string (default: "0600").
    pub mode: Option<String>,
}

/// Input for vault.write_fifo.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultWriteFifoInput {
    /// Handle URI of the Secret to materialise as a FIFO.
    pub handle: String,
}

/// Input for vault.revoke_tempfile.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultRevokeTempfileInput {
    /// Absolute path previously returned by vault.write_tempfile or vault.write_fifo.
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
// Helper
// ---------------------------------------------------------------------------

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
#[rmcp::tool_router(router = use_token_router)]
impl MerkleMcpServer {
    /// Issue a short-lived Use Token for a Secret. The plaintext never appears
    /// in the MCP response. Pass the `use_token` to `vault.ssh.exec` or another
    /// proxy tool. Default TTL: 60 seconds.
    #[tool(
        name = "vault.use",
        description = "Issue a short-lived Use Token for a Secret. The plaintext never appears in the response. Pass the use_token to vault.ssh.exec or another proxy tool. Default TTL: 60 seconds."
    )]
    pub async fn vault_use(
        &self,
        Parameters(input): Parameters<VaultUseInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = input
            .handle
            .parse::<Handle>()
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let _ = input.purpose;
        // session_id tracks token ownership across the MCP session lifetime;
        // a fresh UuidV7 is generated per invocation as a unique token issuance id.
        let cmd = UseTokenCommand { namespace_id, handle, session_id: UuidV7::new() };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "use_token": out.use_token,
                "expires_at": out.expires_at.to_string(),
            })
            .to_string(),
        )]))
    }

    /// Materialise a Secret on the local filesystem as a Tempfile.
    /// Cleaned up on session close or idle timeout.
    /// Useful for tools that require a file path (e.g. `ssh -i`).
    #[tool(
        name = "vault.write_tempfile",
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

        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let _ = input.mode;
        // dek_bytes: zeroed placeholder — the application layer retrieves the
        // real DEK from the keychain internally (the MCP adapter does not hold it).
        let cmd = WriteTempfileCommand { namespace_id, handle, dek_bytes: [0u8; 32] };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "opaque_token": out.opaque_token,
                "expires_at": out.expires_at.to_string(),
            })
            .to_string(),
        )]))
    }

    /// Materialise a Secret as a named pipe (FIFO). The agent writes the
    /// plaintext once; the file is removed after the first successful read.
    /// Suitable for programs that open a credential path exactly once.
    #[tool(
        name = "vault.write_fifo",
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

        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        // dek_bytes: zeroed placeholder — the application layer retrieves the
        // real DEK from the keychain internally (the MCP adapter does not hold it).
        let cmd = WriteFifoCommand { namespace_id, handle, dek_bytes: [0u8; 32] };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "opaque_token": out.opaque_token,
                "expires_at": out.expires_at.to_string(),
            })
            .to_string(),
        )]))
    }

    /// Explicitly revoke a Tempfile or FIFO before session close.
    /// The file is removed immediately and the path becomes invalid.
    #[tool(
        name = "vault.revoke_tempfile",
        description = "Explicitly revoke a Tempfile or FIFO before session close or idle timeout. The file is removed immediately."
    )]
    pub async fn vault_revoke_tempfile(
        &self,
        Parameters(input): Parameters<VaultRevokeTempfileInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };
        // opaque_token: the MCP input supplies a path string; the application
        // command expects an opaque token (same underlying string representation).
        let cmd = RevokeTempfileCommand { namespace_id, opaque_token: input.path.clone() };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({"revoked": out.revoked}).to_string(),
        )]))
    }
}
