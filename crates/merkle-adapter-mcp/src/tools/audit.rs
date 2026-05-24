//! Audit tools: vault.audit.query.
//!
//! Forwards `GET /v1/audit` to the Companion Socket via
//! [`CompanionSocketClient`](merkle_companion_client::CompanionSocketClient).

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
use merkle_companion_client::dto::AuditQuery;

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
    /// Filter by session ID.
    pub session_id: Option<String>,
    /// Filter by outcome.
    pub outcome: Option<String>,
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

#[expect(
    missing_docs,
    reason = "rmcp proc-macro generates the associated fn; doc lives on the #[tool] description attribute"
)]
#[rmcp::tool_router(router = audit_router)]
impl MerkleMcpServer {
    /// Query the append-only Audit Log. Filter by handle, operation type,
    /// session, or outcome. Optionally verify the BLAKE3 hash chain
    /// integrity. Returns at most 500 entries per call.
    #[tool(
        name = "vault.audit.query",
        description = "Query the append-only Audit Log. Filter by handle, operation type, session, or outcome. Optionally verify the BLAKE3 hash chain integrity. Max 500 entries per call."
    )]
    pub async fn vault_audit_query(
        &self,
        Parameters(input): Parameters<VaultAuditQueryInput>,
    ) -> Result<CallToolResult, ErrorData> {
        // Parse session_id UUID if provided.
        let session_id = input
            .session_id
            .as_deref()
            .map(|s| {
                s.parse::<uuid::Uuid>()
                    .map_err(|e| ErrorData::invalid_params(format!("session_id: {e}"), None))
            })
            .transpose()?;

        let out = self
            .client
            .query_audit(&AuditQuery {
                handle: input.handle,
                op: input.op,
                since: None,
                until: None,
                session_id,
                outcome: input.outcome,
                verify_chain: input.verify_chain.unwrap_or(false),
                limit: input.limit.unwrap_or(50),
            })
            .await
            .map_err(client_error_to_mcp)?;

        let entries: Vec<serde_json::Value> = out
            .entries
            .iter()
            .map(|e| {
                json!({
                    "id": e.id.to_string(),
                    "ts": e.ts.to_rfc3339(),
                    "namespace_id": e.namespace_id.to_string(),
                    "op": e.op,
                    "outcome": e.outcome,
                    "handle": e.handle.as_ref().map(ToString::to_string),
                    "purpose": e.purpose,
                    "session_id": e.session_id.to_string(),
                    "caller_pid": e.caller_pid,
                    "caller_program": e.caller_program,
                    "denial_reason": e.denial_reason,
                    "seq": e.seq,
                    "note": e.note,
                    "current_hash": e.current_hash,
                    "prev_hash": e.prev_hash,
                })
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "count": entries.len(),
                "total": out.total,
                "chain_valid": out.chain_valid,
                "entries": entries,
            })
            .to_string(),
        )]))
    }
}
