//! vault.reveal — OOB-gated plaintext disclosure.
//!
//! Forwards `POST /v1/reveal` to the Companion Socket. The agent evaluates
//! the operator confirmation and OOB policy and returns either plaintext
//! (200 OK) or an OOB-pending envelope (202 Accepted).

use rmcp::{
    ErrorData,
    handler::server::{router::tool::ToolRouter, tool::Parameters},
    model::{CallToolResult, Content},
    schemars::{self, JsonSchema},
    tool,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{MerkleMcpServer, errors::client_error_to_mcp};
use merkle_companion_client::dto::OperatorConfirmation;
use merkle_companion_client::{RevealOutcome, dto::RevealRequest};
use merkle_types::Handle;

// ---------------------------------------------------------------------------
// Input parameter struct
// ---------------------------------------------------------------------------

/// Input for vault.reveal.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultRevealInput {
    /// Handle URI of the Secret to reveal (e.g. `vault://default/token/my-token`).
    pub handle: String,
    /// Human-readable reason recorded in the audit log.
    pub purpose: String,
    /// For Claude Code clients: must be `true`. Only honoured when set by
    /// the `/merkle-reveal` slash command, never from LLM-generated arguments.
    pub operator_confirmation: bool,
}

// ---------------------------------------------------------------------------
// Tool group marker type
// ---------------------------------------------------------------------------

/// Marker struct for the reveal tool group.
pub struct RevealTools;

impl RevealTools {
    /// Build a `ToolRouter` containing all reveal tools.
    #[must_use]
    pub fn router() -> ToolRouter<MerkleMcpServer> {
        MerkleMcpServer::reveal_router()
    }
}

// ---------------------------------------------------------------------------
// Tool implementation
// ---------------------------------------------------------------------------

#[expect(
    missing_docs,
    reason = "rmcp proc-macro generates the associated fn; doc lives on the #[tool] description attribute"
)]
#[rmcp::tool_router(router = reveal_router)]
impl MerkleMcpServer {
    /// Return the plaintext of a Secret directly in the MCP response.
    ///
    /// Requires `operator_confirmation = true` (set only by the `/merkle-reveal`
    /// slash command). High-sensitivity Secrets additionally require an OOB
    /// round-trip. If OOB confirmation is pending, a `oob_pending=true` response
    /// is returned with channel and nonce information; the caller should
    /// acknowledge and re-issue the tool call.
    ///
    /// WARNING: The revealed plaintext appears in the conversation context.
    /// Prefer `vault.use` for proxy operations that do not require the model
    /// to see the credential value.
    #[tool(
        name = "vault.reveal",
        description = "Return the plaintext of a Secret in the MCP response. Requires operator_confirmation=true (set only by /merkle-reveal slash command). Triggers OOB confirmation for medium/high sensitivity. If OOB pending, re-issue after acknowledging the notification."
    )]
    pub async fn vault_reveal(
        &self,
        Parameters(input): Parameters<VaultRevealInput>,
    ) -> Result<CallToolResult, ErrorData> {
        if !input.operator_confirmation {
            return Err(crate::errors::not_implemented("vault.reveal"));
        }

        let handle = input
            .handle
            .parse::<Handle>()
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        let session_id = {
            let session = self.session.read().await;
            session
                .namespace_label()
                .ok_or_else(crate::errors::namespace_not_bound)?;
            session
                .session_id()
                .ok_or_else(crate::errors::namespace_not_bound)?
        };

        let outcome = self
            .client
            .reveal(RevealRequest {
                handle,
                reason: input.purpose,
                session_id,
                operator_confirmation: OperatorConfirmation {
                    slash_command: input.operator_confirmation,
                    oob_ack: false,
                    oob_channel: None,
                },
            })
            .await
            .map_err(client_error_to_mcp)?;

        match outcome {
            RevealOutcome::Plaintext(resp) => Ok(CallToolResult::success(vec![Content::text(
                json!({
                    "plaintext": resp.plaintext,
                    "revealed_at": resp.revealed_at.to_rfc3339(),
                    "warning": resp.warning,
                })
                .to_string(),
            )])),
            RevealOutcome::OobPending(resp) => Ok(CallToolResult::success(vec![Content::text(
                json!({
                    "oob_pending": resp.oob_pending,
                    "oob_channel": format!("{:?}", resp.oob_channel),
                    "expires_at": resp.expires_at.to_rfc3339(),
                    "request_nonce": resp.request_nonce,
                    "instructions": "Acknowledge the OOB notification and re-issue vault.reveal.",
                })
                .to_string(),
            )])),
        }
    }
}
