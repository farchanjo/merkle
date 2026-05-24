//! Diagnostics tools: vault.doctor.
//!
//! `DoctorQuery` is fully implemented (F5.B) and aggregates health checks
//! across all bounded contexts.

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
use merkle_application::queries::doctor::DoctorQuery;

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

#[allow(missing_docs)]
#[rmcp::tool_router(router = diagnostics_router)]
impl MerkleMcpServer {
    /// Run a diagnostic health check on the Vault Agent. Always returns a
    /// result even in degraded state. Reports: sealed state, keychain,
    /// DB integrity, audit chain, backup schedule, expiring Secrets, disk
    /// space, and warnings.
    #[tool(
        name = "vault.doctor",
        description = "Run a diagnostic health check on the Vault Agent. Always returns a result even in degraded state. Reports: sealed state, keychain, DB integrity, audit chain, backup schedule, expiring Secrets, disk space, and warnings."
    )]
    pub async fn vault_doctor(
        &self,
        Parameters(_input): Parameters<VaultDoctorInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let query = DoctorQuery;
        let out = query
            .execute(&self.app_ctx)
            .await
            .map_err(app_error_to_mcp)?;

        let checks: Vec<serde_json::Value> = out
            .checks
            .iter()
            .map(|c| {
                json!({
                    "name": c.name,
                    "ok": c.ok,
                    "detail": c.detail,
                })
            })
            .collect();

        let chain_intact = out
            .checks
            .iter()
            .find(|c| c.name == "audit_chain_integrity")
            .is_some_and(|c| c.ok);

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "sealed_state": out.sealed_state,
                "all_ok": out.all_ok,
                "chain_intact": chain_intact,
                "checks": checks,
            })
            .to_string(),
        )]))
    }
}
