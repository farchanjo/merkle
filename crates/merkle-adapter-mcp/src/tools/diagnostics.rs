//! Diagnostics tools: vault.doctor.
//!
//! Forwards `GET /v1/agent/doctor` to the Companion Socket via
//! [`CompanionSocketClient`](merkle_companion_client::CompanionSocketClient).

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

// ---------------------------------------------------------------------------
// Input parameter struct
// ---------------------------------------------------------------------------

/// Input for vault.doctor — no parameters required.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct VaultDoctorInput {}

// ---------------------------------------------------------------------------
// Tool group marker type
// ---------------------------------------------------------------------------

/// Marker struct for the diagnostics tool group.
pub struct DiagnosticsTools;

impl DiagnosticsTools {
    /// Build a `ToolRouter` containing all diagnostics tools.
    #[must_use]
    pub fn router() -> ToolRouter<MerkleMcpServer> {
        MerkleMcpServer::diagnostics_router()
    }
}

// ---------------------------------------------------------------------------
// Tool implementation
// ---------------------------------------------------------------------------

#[allow(
    missing_docs,
    reason = "rmcp proc-macro generates the associated fn; doc lives on the #[tool] description attribute"
)]
#[rmcp::tool_router(router = diagnostics_router)]
impl MerkleMcpServer {
    /// Run a diagnostic health check on the Vault Agent. Always returns a
    /// result even in degraded state. Reports sealed state, keychain
    /// reachability, DB integrity, audit chain, backup schedule, expiring
    /// Secrets, disk space, and any warnings.
    #[tool(
        name = "vault.doctor",
        description = "Run a diagnostic health check on the Vault Agent. Always returns a result even in degraded state. Reports: sealed state, keychain, DB integrity, audit chain, backup schedule, expiring Secrets, disk space, and warnings."
    )]
    pub async fn vault_doctor(
        &self,
        Parameters(_input): Parameters<VaultDoctorInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .client
            .agent_doctor()
            .await
            .map_err(client_error_to_mcp)?;

        let checks: Vec<serde_json::Value> = out
            .checks
            .iter()
            .map(|c| {
                json!({
                    "name": c.name,
                    "status": c.status,
                    "message": c.message,
                    "duration_ms": c.duration_ms,
                })
            })
            .collect();

        let all_pass = out.checks.iter().all(|c| c.status == "pass");

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "overall": out.overall,
                "all_pass": all_pass,
                "checks": checks,
            })
            .to_string(),
        )]))
    }
}
