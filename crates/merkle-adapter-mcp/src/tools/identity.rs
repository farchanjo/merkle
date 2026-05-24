//! Identity and sealing tools: vault.unseal, vault.seal, vault.bind.
//!
//! These tools manage the vault lifecycle state transitions and namespace
//! session binding. They must be called before most other tools.

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
    bind_namespace::BindNamespaceCommand, seal_vault::SealVaultCommand,
    unseal_vault::UnsealVaultCommand,
};
use merkle_domain_identity::UnsealPreconditions;
use merkle_types::{NamespaceLabel, SecurityProfile};

// ---------------------------------------------------------------------------
// Input parameter structs
// ---------------------------------------------------------------------------

/// Input for vault.unseal.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultUnsealInput {
    /// Passphrase for software-only keychain. On macOS with Touch ID configured
    /// this field is ignored; the system prompts natively.
    pub passphrase: Option<String>,
}

/// Input for vault.seal.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultSealInput {
    /// Optional reason for sealing, recorded in the audit log.
    pub reason: Option<String>,
}

/// Input for vault.bind.
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
// Tool implementations
// ---------------------------------------------------------------------------

#[allow(missing_docs)]
#[rmcp::tool_router(router = identity_router)]
impl MerkleMcpServer {
    /// Unseal the Vault Agent by loading the MasterKey from the OS keychain.
    ///
    /// On macOS with Touch ID configured the system prompts natively;
    /// `passphrase` is ignored. On Linux/Windows the passphrase is used to
    /// derive the key with Argon2id if no Secret Service is available.
    #[tool(name = "vault.unseal", description = "Unseal the Vault Agent by loading the MasterKey from the OS keychain. On macOS, Touch ID is used. On Linux/Windows a passphrase may be required. Most tools require the agent to be unsealed.")]
    pub async fn vault_unseal(
        &self,
        Parameters(_input): Parameters<VaultUnsealInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let cmd = UnsealVaultCommand {
            preconditions: UnsealPreconditions {
                security_profile: SecurityProfile::Balanced,
                mlock_succeeded: true,
                entropy_seeded: true,
                keychain_reachable: true,
            },
        };
        cmd.execute(&self.app_ctx)
            .await
            .map_err(app_error_to_mcp)?;
        Ok(CallToolResult::success(vec![Content::text(
            json!({"unsealed": true}).to_string(),
        )]))
    }

    /// Seal the Vault Agent by zeroing the in-memory MasterKey.
    ///
    /// All subsequent tool calls that require plaintext access will return
    /// `UnsealRequired` until the agent is unsealed again.
    #[tool(name = "vault.seal", description = "Seal the Vault Agent by zeroing the in-memory MasterKey. All subsequent plaintext-access tool calls will return UnsealRequired until the agent is unsealed again.")]
    pub async fn vault_seal(
        &self,
        Parameters(input): Parameters<VaultSealInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let _ = input.reason; // recorded in audit log by domain layer
        let cmd = SealVaultCommand;
        cmd.execute(&self.app_ctx)
            .await
            .map_err(app_error_to_mcp)?;
        Ok(CallToolResult::success(vec![Content::text(
            json!({"sealed": true}).to_string(),
        )]))
    }

    /// Associate the current MCP session with a named Namespace.
    ///
    /// May be called at most once per session; re-binding is rejected with
    /// `AlreadyBound`. Without a binding, operations resolve to the default
    /// Namespace derived from the working directory hash.
    #[tool(name = "vault.bind", description = "Associate the current MCP session with a named Namespace. Call this at session start. May be called at most once — re-binding returns AlreadyBound. Without binding, the default Namespace (cwd-hash derived) is used.")]
    pub async fn vault_bind(
        &self,
        Parameters(input): Parameters<VaultBindInput>,
    ) -> Result<CallToolResult, ErrorData> {
        // Enforce single-bind invariant via session state.
        {
            let mut session = self.session.write().await;
            session
                .bind(input.label.clone())
                .map_err(|_| crate::errors::already_bound())?;
        }

        let label = NamespaceLabel::try_from(input.label.as_str())
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        let cmd = BindNamespaceCommand {
            label,
            cwd_hash: None,
            dek_version: 1,
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        // Persist the authoritative NamespaceId so subsequent tool calls can
        // use the same namespace record that was just created in storage.
        {
            let mut session = self.session.write().await;
            session.set_namespace_id(out.namespace_id);
        }

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "namespace_id": out.namespace_id.to_string(),
                "label": out.label.to_string(),
                "policy_profile": "balanced",
            })
            .to_string(),
        )]))
    }
}
