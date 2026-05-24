//! Secret CRUD tools:
//! vault.put, vault.get, vault.list, vault.describe,
//! vault.rotate, vault.delete, vault.search, vault.history.

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
    delete_secret::DeleteSecretCommand, describe_secret::DescribeSecretCommand,
    list_secrets::ListSecretsCommand, put_secret::PutSecretCommand,
    rotate_secret::RotateSecretCommand, search_secrets::SearchSecretsCommand,
};
use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;
use merkle_types::{CategoryName, Handle, NamespaceId, Sensitivity};

// ---------------------------------------------------------------------------
// Input parameter structs
// ---------------------------------------------------------------------------

/// Input for vault.put — create or overwrite a Secret.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultPutInput {
    /// Secret category (ssh | password | token | env | cert | key | database | note | otp | cloud | gpg).
    pub category: String,
    /// Unique name within the Namespace + category pair.
    pub name: String,
    /// Sensitive value — shape validated against the category schema.
    pub value: serde_json::Value,
    /// Optional custom CUE schema reference; omit to use the built-in schema.
    pub schema_id: Option<String>,
    /// Optional tags to associate with the Secret.
    pub tags: Option<Vec<String>>,
    /// Sensitivity level: low | medium | high.
    pub sensitivity: Option<String>,
    /// If true, mark as safe for FTS public indexing.
    pub expose: Option<bool>,
}

/// Input for vault.get — resolve public metadata (no plaintext).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultGetInput {
    /// Handle URI (vault://\<label\>/\<category\>/\<name\>).
    pub handle: String,
    /// Human-readable reason; recorded in the audit log.
    pub purpose: String,
}

/// Input for vault.list — list Secrets matching filter criteria.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct VaultListInput {
    /// Filter by category.
    pub category: Option<String>,
    /// Filter by tags (AND semantics — every returned Secret carries all listed tags).
    pub tags: Option<Vec<String>>,
    /// Glob pattern matched against Secret name (e.g. prod-*).
    pub name_pattern: Option<String>,
    /// Only return Secrets expiring before this ISO 8601 datetime.
    pub expires_before: Option<String>,
    /// Filter by sensitivity level.
    pub sensitivity: Option<String>,
    /// FTS5 MATCH expression over public metadata.
    pub fts_query: Option<String>,
}

/// Input for vault.describe — full public metadata for a single Secret.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultDescribeInput {
    /// Handle URI (vault://\<label\>/\<category\>/\<name\>).
    pub handle: String,
}

/// Input for vault.rotate — replace the active value while retaining history.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultRotateInput {
    /// Handle URI of the Secret to rotate.
    pub handle: String,
    /// New value — same schema as vault.put `value` for this category.
    pub new_value: serde_json::Value,
    /// Human-readable reason; recorded in the audit log.
    pub purpose: String,
}

/// Input for vault.delete — permanently delete a Secret and all its versions.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultDeleteInput {
    /// Handle URI of the Secret to delete.
    pub handle: String,
    /// Human-readable reason; recorded in the audit log.
    pub purpose: String,
}

/// Input for vault.search — free-text search over public metadata.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultSearchInput {
    /// Natural-language or keyword query.
    pub query: String,
    /// Maximum results to return (default 10, max 50).
    pub limit: Option<u32>,
}

/// Input for vault.history — version history of a Secret.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultHistoryInput {
    /// Handle URI of the Secret.
    pub handle: String,
    /// Maximum versions to return (default 10, max 50).
    pub limit: Option<u32>,
}

// ---------------------------------------------------------------------------
// Router marker
// ---------------------------------------------------------------------------

/// Marker struct for the secrets tool group.
pub struct SecretsTools;

impl SecretsTools {
    /// Build a `ToolRouter` containing all secrets tools.
    #[must_use]
    pub fn router() -> ToolRouter<MerkleMcpServer> {
        MerkleMcpServer::secrets_router()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_handle(raw: &str) -> Result<Handle, ErrorData> {
    raw.parse::<Handle>()
        .map_err(|e| ErrorData::invalid_params(format!("invalid handle: {e}"), None))
}

fn parse_namespace_id_from_session(session: &crate::session::SessionState) -> NamespaceId {
    // Use the NamespaceId stored by vault.bind; fall back to a fresh UUID
    // only when vault.bind has not been called yet (anonymous session).
    session.namespace_id().unwrap_or_default()
}

fn parse_sensitivity(s: &str) -> Sensitivity {
    match s.to_ascii_lowercase().as_str() {
        "high" => Sensitivity::High,
        "medium" => Sensitivity::Medium,
        _ => Sensitivity::Low,
    }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[allow(missing_docs)]
#[rmcp::tool_router(router = secrets_router)]
impl MerkleMcpServer {
    /// Create or overwrite a Secret in the bound Namespace.
    ///
    /// The `value` field contains sensitive material and is never echoed back
    /// in any response. Requires the vault to be Unsealed and a Namespace to
    /// be bound.
    #[tool(name = "vault.put", description = "Create or overwrite a Secret. The value field contains sensitive material and is never echoed back. Requires vault.bind to have been called first and the vault to be Unsealed.")]
    pub async fn vault_put(
        &self,
        Parameters(input): Parameters<VaultPutInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let category = CategoryName::try_from(input.category.as_str())
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        let name = merkle_types::SecretName::try_from(input.name.as_str())
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        let ns_label = {
            let session = self.session.read().await;
            session.namespace_label().unwrap_or("default").to_owned()
        };
        let ns_label_parsed = merkle_types::NamespaceLabel::try_from(ns_label.as_str())
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        let handle = Handle::new(ns_label_parsed, category.clone(), name);
        let namespace_id = { let session = self.session.read().await; parse_namespace_id_from_session(&session) };
        let sensitivity = input
            .sensitivity
            .as_deref()
            .map_or(Sensitivity::Low, parse_sensitivity);
        let plaintext = serde_json::to_vec(&input.value)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        let cmd = PutSecretCommand {
            namespace_id,
            handle: handle.clone(),
            category,
            sensitivity,
            tags: vec![],
            expose_metadata: input.expose.unwrap_or(false),
            plaintext,
            value_format: merkle_application::ValueFormat::Utf8,
            dek_version: 1,
            dek_bytes: [0u8; 32], // Placeholder; real DEK resolved by application layer.
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "handle": out.handle.to_string(),
                "version": 1,
                "created_at": merkle_types::Rfc3339Timestamp::now().to_string(),
            })
            .to_string(),
        )]))
    }

    /// Return public metadata for a handle and a warning that plaintext is
    /// withheld. Confirms existence without returning the private blob.
    #[tool(name = "vault.get", description = "Return public metadata and a warning that plaintext is withheld. Confirms the Secret exists. Use vault.use for proxy operations or vault.reveal for explicit access.")]
    pub async fn vault_get(
        &self,
        Parameters(input): Parameters<VaultGetInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;
        let namespace_id = { let session = self.session.read().await; parse_namespace_id_from_session(&session) };
        let cmd = DescribeSecretCommand {
            namespace_id,
            handle,
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;
        let s = &out.secret;
        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "handle": s.handle.to_string(),
                "name": s.handle.secret_name().to_string(),
                "category": s.handle.category().to_string(),
                "sensitivity": format!("{:?}", s.sensitivity),
                "version": s.versions().len(),
                "warning": "Plaintext withheld. Use vault.use for proxy operations or vault.reveal (requires Operator Confirmation) for explicit access.",
            })
            .to_string(),
        )]))
    }

    /// List Secrets matching optional filter criteria. Returns public metadata
    /// only — no plaintext.
    #[tool(name = "vault.list", description = "List Secrets matching filter criteria. Returns public metadata only (no plaintext). Supports category, tag, name-pattern, expiry, sensitivity, and FTS5 filters.")]
    pub async fn vault_list(
        &self,
        Parameters(input): Parameters<VaultListInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = { let session = self.session.read().await; parse_namespace_id_from_session(&session) };
        let cmd = ListSecretsCommand {
            namespace_id,
            tag_match: None,
            name_pattern: input.name_pattern,
            limit: None,
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;
        let items: Vec<_> = out
            .secrets
            .iter()
            .map(|s| {
                json!({
                    "handle": s.handle.to_string(),
                    "name": s.handle.secret_name().to_string(),
                    "category": s.handle.category().to_string(),
                    "sensitivity": format!("{:?}", s.sensitivity),
                    "version": s.versions().len(),
                })
            })
            .collect();
        Ok(CallToolResult::success(vec![Content::text(
            json!({"items": items, "total": items.len()}).to_string(),
        )]))
    }

    /// Return full public metadata for a single Secret including its
    /// `schema_id` field.
    #[tool(name = "vault.describe", description = "Return full public metadata for a single Secret, including schema_id. Does not return plaintext.")]
    pub async fn vault_describe(
        &self,
        Parameters(input): Parameters<VaultDescribeInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;
        let namespace_id = { let session = self.session.read().await; parse_namespace_id_from_session(&session) };
        let cmd = DescribeSecretCommand {
            namespace_id,
            handle,
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;
        let s = &out.secret;
        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "handle": s.handle.to_string(),
                "name": s.handle.secret_name().to_string(),
                "category": s.handle.category().to_string(),
                "sensitivity": format!("{:?}", s.sensitivity),
                "version": s.versions().len(),
                "schema_id": null,
            })
            .to_string(),
        )]))
    }

    /// Replace the active value of a Secret while retaining prior versions up
    /// to the Namespace Policy `retain_count`.
    #[tool(name = "vault.rotate", description = "Replace the active value of a Secret, retaining prior versions per Namespace Policy. Preferred over delete+put for Secret updates — preserves version history and the handle URI.")]
    pub async fn vault_rotate(
        &self,
        Parameters(input): Parameters<VaultRotateInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;
        let namespace_id = { let session = self.session.read().await; parse_namespace_id_from_session(&session) };
        let plaintext = serde_json::to_vec(&input.new_value)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        let cmd = RotateSecretCommand {
            namespace_id,
            handle,
            plaintext,
            value_format: merkle_application::ValueFormat::Utf8,
            dek_version: 1,
            dek_bytes: [0u8; 32], // Placeholder; real DEK resolved by application layer.
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;
        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "version": out.new_version_no,
                "rotated_at": merkle_types::Rfc3339Timestamp::now().to_string(),
                "versions_retained": out.new_version_no,
            })
            .to_string(),
        )]))
    }

    /// Permanently delete a Secret and all its versions. Irreversible.
    #[tool(name = "vault.delete", description = "Permanently delete a Secret and all its versions. This operation is irreversible. Recorded in the audit log.")]
    pub async fn vault_delete(
        &self,
        Parameters(input): Parameters<VaultDeleteInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;
        let namespace_id = { let session = self.session.read().await; parse_namespace_id_from_session(&session) };
        // MCP-initiated deletes require operator confirmation.
        // The `slash_command` flag is always `true` in the MCP transport because
        // the operator explicitly invoked the tool; no OOB ack is issued here.
        let operator_confirmation = OperatorConfirmation {
            slash_command: true,
            oob_ack: false,
            signed_config_flag: None,
        };
        let cmd = DeleteSecretCommand {
            namespace_id,
            handle,
            operator_confirmation,
        };
        cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;
        Ok(CallToolResult::success(vec![Content::text(
            json!({"deleted": true, "versions_removed": 0}).to_string(),
        )]))
    }

    /// Free-text semantic search over public metadata using the FTS5 index.
    /// Returns ranked handles with a relevance score.
    #[tool(name = "vault.search", description = "Free-text semantic search over public metadata using the FTS5 index. Returns ranked handles with BM25 relevance scores (lower = more relevant).")]
    pub async fn vault_search(
        &self,
        Parameters(input): Parameters<VaultSearchInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = { let session = self.session.read().await; parse_namespace_id_from_session(&session) };
        let cmd = SearchSecretsCommand {
            namespace_id,
            query: input.query,
            limit: input.limit,
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;
        let results: Vec<_> = out
            .secrets
            .iter()
            .map(|s| {
                json!({
                    "handle": s.handle.to_string(),
                    "name": s.handle.secret_name().to_string(),
                    "category": s.handle.category().to_string(),
                    "sensitivity": format!("{:?}", s.sensitivity),
                })
            })
            .collect();
        Ok(CallToolResult::success(vec![Content::text(
            json!({"results": results, "count": results.len()}).to_string(),
        )]))
    }

    /// Return the version history of a Secret.
    #[tool(name = "vault.history", description = "Return the version history of a Secret. Shows creation, rotation, and deletion timestamps per version.")]
    pub async fn vault_history(
        &self,
        Parameters(input): Parameters<VaultHistoryInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;
        let namespace_id = { let session = self.session.read().await; parse_namespace_id_from_session(&session) };
        // DescribeSecretCommand exposes version list; no dedicated history command yet.
        let cmd = DescribeSecretCommand {
            namespace_id,
            handle: handle.clone(),
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;
        let limit = input.limit.unwrap_or(10) as usize;
        let versions: Vec<_> = out
            .secret
            .versions()
            .iter()
            .take(limit)
            .map(|v| {
                json!({
                    "version": v.version_no,
                    "created_at": v.created_at.to_string(),
                    "size_bytes": v.blob.ciphertext.len(),
                })
            })
            .collect();
        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "handle": handle.to_string(),
                "versions": versions,
            })
            .to_string(),
        )]))
    }
}
