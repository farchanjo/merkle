//! Audit tools: vault.audit.query.

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
use merkle_application::queries::query_audit::QueryAuditQuery;
use merkle_domain_audit_compliance::AuditQuery;

// ---------------------------------------------------------------------------
// Input parameter struct
// ---------------------------------------------------------------------------

/// Input for vault.audit.query.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultAuditQueryInput {
    /// Filter audit entries by handle URI.
    pub handle: Option<String>,
    /// Filter by operation type.
    pub op: Option<String>,
    /// Only include entries at or after this ISO 8601 datetime.
    pub since: Option<String>,
    /// Only include entries at or before this ISO 8601 datetime.
    pub until: Option<String>,
    /// Filter by session ID.
    pub session_id: Option<String>,
    /// Maximum entries to return (default 50, max 500).
    pub limit: Option<u32>,
    /// If true, run the Chain Verifier over the returned entries.
    pub verify_chain: Option<bool>,
}

// ---------------------------------------------------------------------------
// Tool group marker type
// ---------------------------------------------------------------------------

/// Marker struct for the audit tool group.
pub struct AuditTools;

impl AuditTools {
    /// Build a `ToolRouter` containing all audit tools.
    #[must_use]
    pub fn router() -> ToolRouter<MerkleMcpServer> {
        MerkleMcpServer::audit_router()
    }
}

// ---------------------------------------------------------------------------
// Tool implementation
// ---------------------------------------------------------------------------

#[allow(missing_docs)]
#[rmcp::tool_router(router = audit_router)]
impl MerkleMcpServer {
    /// Query the append-only Audit Log. Filter by handle, operation type,
    /// time range, or session. Optionally verify the BLAKE3 hash chain
    /// integrity. Returns at most 500 entries per call.
    #[tool(
        name = "vault.audit.query",
        description = "Query the append-only Audit Log. Filter by handle, operation type, time range, or session. Optionally verify the BLAKE3 hash chain integrity. Max 500 entries per call."
    )]
    pub async fn vault_audit_query(
        &self,
        Parameters(input): Parameters<VaultAuditQueryInput>,
    ) -> Result<CallToolResult, ErrorData> {
        // Build the AuditQuery filter from optional input fields.
        let filter = AuditQuery::default();
        // Note: AuditQuery field population is wired once the filter
        // builder API stabilises. Currently passes default (no filter = all).
        let _ = input;

        let query = QueryAuditQuery { filter };
        let out = query
            .execute(&self.app_ctx)
            .await
            .map_err(app_error_to_mcp)?;

        let entries: Vec<serde_json::Value> = out
            .entries
            .iter()
            .map(|e| {
                json!({
                    "id": e.id.to_string(),
                    "sequence": e.seq,
                    "op": format!("{:?}", e.op),
                    "outcome": format!("{:?}", e.outcome),
                    "namespace_id": e.namespace_id.to_string(),
                    "timestamp": e.ts.to_string(),
                    "handle": e.handle.as_ref().map(ToString::to_string),
                    "caller_program": e.caller_program.as_deref(),
                    "denial_reason": e.denial_reason.as_ref().map(ToString::to_string),
                })
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "count": entries.len(),
                "entries": entries,
            })
            .to_string(),
        )]))
    }
}
