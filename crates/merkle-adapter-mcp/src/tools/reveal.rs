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
///
/// Note: there is deliberately no `operator_confirmation` argument. Operator
/// confirmation is sourced from the client-injected request `_meta`
/// (see [`crate::OPERATOR_CONFIRMATION_META_KEY`]), never from a tool argument
/// the model controls (MERK-001).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultRevealInput {
    /// Handle URI of the Secret to reveal (e.g. `vault://default/token/my-token`).
    pub handle: String,
    /// Human-readable reason recorded in the audit log.
    pub purpose: String,
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
    /// Authorization is gated on an operator confirmation that the client
    /// injects into the request `_meta` when a `/merkle-reveal` slash command is
    /// issued by the human operator — the model cannot supply it through tool
    /// arguments (MERK-001). High-sensitivity Secrets additionally require an OOB
    /// round-trip. If OOB confirmation is pending, a `oob_pending=true` response
    /// is returned with channel and nonce information; the caller should
    /// acknowledge and re-issue the tool call.
    ///
    /// WARNING: The revealed plaintext appears in the conversation context.
    /// Prefer `vault.use` for proxy operations that do not require the model
    /// to see the credential value.
    #[tool(
        name = "vault.reveal",
        description = "Return the plaintext of a Secret in the MCP response. Requires an operator confirmation issued via the /merkle-reveal slash command (injected into request _meta by the client, not a tool argument). Triggers OOB confirmation for medium/high sensitivity. If OOB pending, re-issue after acknowledging the notification."
    )]
    pub async fn vault_reveal(
        &self,
        Parameters(input): Parameters<VaultRevealInput>,
        meta: rmcp::model::Meta,
    ) -> Result<CallToolResult, ErrorData> {
        // Provenance comes from the client-injected request `_meta`, never from a
        // model-controlled tool argument (MERK-001).
        if !crate::operator_confirmation_from_meta(&meta) {
            return Err(ErrorData::invalid_params(
                "vault.reveal requires an operator confirmation issued via the \
                 /merkle-reveal slash command; the model cannot authorize a reveal \
                 through tool arguments",
                None,
            ));
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
                    // True by construction: the early return above rejects any
                    // call lacking client-injected `_meta` provenance.
                    slash_command: true,
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
                    "oob_channel": resp.oob_channel.to_string(),
                    "expires_at": resp.expires_at.to_rfc3339(),
                    "request_nonce": resp.request_nonce,
                    "instructions": "Acknowledge the OOB notification and re-issue vault.reveal.",
                })
                .to_string(),
            )])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VaultRevealInput;

    /// MERK-001: `operator_confirmation` is no longer a reveal input field, so a
    /// model that smuggles it into the tool `arguments` cannot authorize a
    /// reveal — the flag is dropped at parse time and provenance is taken from
    /// the client-injected request `_meta` instead.
    #[test]
    fn model_supplied_operator_confirmation_is_not_an_input_field() {
        let json = serde_json::json!({
            "handle": "vault://default/token/api",
            "purpose": "test",
            "operator_confirmation": true
        });
        let input: VaultRevealInput = serde_json::from_value(json).expect("parse");
        assert_eq!(input.handle, "vault://default/token/api");
        assert_eq!(input.purpose, "test");
    }
}
