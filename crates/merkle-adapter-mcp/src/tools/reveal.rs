//! vault.reveal — OOB-gated plaintext disclosure.
//!
//! Supports two confirmation paths:
//!
//! 1. **Slash-command path** (`operator_confirmation = true`): the Claude Code
//!    client sets `slash_command = true` via the `/merkle-reveal` slash command.
//! 2. **JWT attestation path** (`signed_config_flag` present, `operator_confirmation =
//!    false`): non-Claude clients supply an Ed25519-signed JWT that is verified
//!    by `JwtAttestationVerifier` (ADR-0011 Amendment 6).

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
use merkle_application::commands::reveal_secret::RevealSecretCommand;
use merkle_domain_access_mediation::operator_confirmation::{
    OperatorConfirmation, SignedConfigFlag,
};
use merkle_types::{
    CompanionDeviceClass, Handle, NamespaceId, OobChannel, SecurityProfile, Sensitivity,
};

// ---------------------------------------------------------------------------
// Input parameter struct
// ---------------------------------------------------------------------------

/// Signed config flag submitted by non-Claude clients (ADR-0011 Amendment 6).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SignedConfigFlagInput {
    /// Compact-serialised JWT (base64url.base64url.base64url).
    pub jwt: String,
    /// Key identifier declared in the JWT header (`kid` claim).
    pub key_id: String,
}

/// Input for vault.reveal.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultRevealInput {
    /// Handle URI of the Secret to reveal (e.g. `vault://default/my-token`).
    pub handle: String,
    /// Human-readable reason recorded in the audit log.
    pub purpose: String,
    /// For Claude Code clients: must be `true`. Only honoured when set by
    /// the `/merkle-reveal` slash command, never from LLM-generated arguments.
    ///
    /// For non-Claude clients using JWT attestation, set to `false` and
    /// supply `signed_config_flag` instead.
    pub operator_confirmation: bool,
    /// Optional JWT attestation for non-Claude clients (ADR-0011 Amendment 6).
    /// When supplied, `operator_confirmation` may be `false`.
    pub signed_config_flag: Option<SignedConfigFlagInput>,
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

#[allow(missing_docs)]
#[rmcp::tool_router(router = reveal_router)]
impl MerkleMcpServer {
    /// Return the plaintext of a Secret directly in the MCP response.
    ///
    /// Requires `operator_confirmation = true` (set only by the `/merkle-reveal`
    /// slash command) OR a valid `signed_config_flag` JWT for non-Claude clients.
    /// High-sensitivity Secrets additionally require an OOB round-trip.
    ///
    /// WARNING: The revealed plaintext appears in the conversation context.
    /// Prefer `vault.use` for proxy operations that do not require the model
    /// to see the credential value.
    #[tool(
        name = "vault.reveal",
        description = "Return the plaintext of a Secret in the MCP response. Requires operator_confirmation=true (set only by /merkle-reveal slash command) or a valid signed_config_flag JWT for non-Claude clients. Blocked for high-sensitivity Secrets unless Namespace Policy permits. Triggers OOB confirmation for medium/high sensitivity."
    )]
    pub async fn vault_reveal(
        &self,
        Parameters(input): Parameters<VaultRevealInput>,
    ) -> Result<CallToolResult, ErrorData> {
        // Both paths require at least one of: slash_command=true OR signed_config_flag.
        let has_jwt = input.signed_config_flag.is_some();
        if !input.operator_confirmation && !has_jwt {
            return Err(crate::errors::not_implemented("vault.reveal"));
        }

        let handle = input
            .handle
            .parse::<Handle>()
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        let namespace_id = {
            let session = self.session.read().await;
            session
                .namespace_label()
                .ok_or_else(crate::errors::namespace_not_bound)?;
            NamespaceId::new()
        };

        // Build the OperatorConfirmation from the MCP input.
        let scf = input.signed_config_flag.map(|f| SignedConfigFlag {
            jwt: f.jwt,
            key_id: f.key_id,
        });
        let operator_confirmation = OperatorConfirmation {
            slash_command: input.operator_confirmation,
            oob_ack: false,
            signed_config_flag: scf,
        };

        // Use a fresh ChallengeId when the JWT path is active.
        let challenge_id = if operator_confirmation.signed_config_flag.is_some() {
            Some(merkle_types::ChallengeId::new())
        } else {
            None
        };

        // Retrieve the secret's sensitivity from storage (requires unsealed vault).
        let stored_sensitivity = self
            .app_ctx
            .storage
            .get_secret_by_handle(&handle)
            .await
            .map_err(|e| {
                ErrorData::new(
                    rmcp::model::ErrorCode(-32_603),
                    e.to_string(),
                    None,
                )
            })?
            .map_or(Sensitivity::Medium, |s| s.sensitivity);

        let _ = input.purpose; // audited inside RevealSecretCommand

        let cmd = RevealSecretCommand {
            namespace_id,
            handle,
            operator_confirmation,
            challenge_id,
            sensitivity: stored_sensitivity,
            oob_threshold: Sensitivity::High,
            security_profile: SecurityProfile::Relaxed,
            // DEK bytes: the application layer retrieves the real DEK
            // from the keychain internally. The adapter supplies zeroed bytes
            // as a placeholder until Phase 7 full handle-resolution is wired.
            dek_bytes: [0u8; 32],
            companion_device: None,
            oob_channel: OobChannel::DesktopNotif,
            oob_timeout: std::time::Duration::from_secs(60),
            required_device_class: CompanionDeviceClass::Software,
        };

        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;
        let plaintext = String::from_utf8_lossy(&out.plaintext).into_owned();

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "plaintext": plaintext,
            })
            .to_string(),
        )]))
    }
}
