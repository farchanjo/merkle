//! Secret CRUD tools:
//! vault.put, vault.get, vault.list, vault.describe,
//! vault.rotate, vault.delete, vault.search, vault.history.
//!
//! All operations are forwarded to the Vault Agent Companion Socket via
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
use uuid::Uuid;

use crate::{MerkleMcpServer, errors::client_error_to_mcp};
use merkle_companion_client::dto::{
    DeleteSecretRequest, ListSecretsParams, OperatorConfirmationDeleteSecret, PutSecretRequest,
    RotateSecretRequest,
};
use merkle_types::Handle;

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
    /// Maximum results to return (default 50).
    pub limit: Option<u32>,
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

/// Percent-encode the handle URI for embedding in URL path segments.
fn encode_handle(handle: &Handle) -> String {
    let raw = handle.to_string();
    // Replace '/' with %2F so axum routing doesn't split on it.
    raw.replace('/', "%2F")
}

fn resolve_namespace(session: &crate::session::SessionState) -> Result<Uuid, ErrorData> {
    session
        .namespace_id()
        .ok_or_else(crate::errors::namespace_not_bound)
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[expect(
    missing_docs,
    reason = "rmcp proc-macro generates the associated fn; doc lives on the #[tool] description attribute"
)]
#[rmcp::tool_router(router = secrets_router)]
impl MerkleMcpServer {
    /// Create or overwrite a Secret in the bound Namespace.
    ///
    /// The `value` field contains sensitive material and is never echoed back
    /// in any response. Requires the vault to be Unsealed and a Namespace to
    /// be bound.
    #[tool(
        name = "vault.put",
        description = "Create or overwrite a Secret. The value field contains sensitive material and is never echoed back. Requires vault.bind to have been called first and the vault to be Unsealed."
    )]
    pub async fn vault_put(
        &self,
        Parameters(input): Parameters<VaultPutInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let resp = self
            .client
            .put_secret(
                namespace_id,
                PutSecretRequest {
                    name: input.name,
                    category: input.category,
                    value: input.value,
                    value_format: merkle_companion_client::dto::ValueFormatDto::Utf8,
                    schema_id: input.schema_id,
                    tags: vec![],
                    sensitivity: None,
                    description: None,
                    expose: input.expose.unwrap_or(false),
                    expires_at: None,
                    force: false,
                },
            )
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "handle": resp.handle.to_string(),
                "version": resp.version,
                "created_at": resp.created_at.to_rfc3339(),
                "duplicate_fingerprint_warning": resp.duplicate_fingerprint_warning,
            })
            .to_string(),
        )]))
    }

    /// Return public metadata for a handle and a warning that plaintext is
    /// withheld. Confirms existence without returning the private blob.
    #[tool(
        name = "vault.get",
        description = "Return public metadata and a warning that plaintext is withheld. Confirms the Secret exists. Use vault.use for proxy operations or vault.reveal for explicit access."
    )]
    pub async fn vault_get(
        &self,
        Parameters(input): Parameters<VaultGetInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };
        let _ = input.purpose;

        let s = self
            .client
            .get_secret(namespace_id, &encode_handle(&handle))
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "handle": s.handle.to_string(),
                "name": s.name,
                "category": s.category,
                "sensitivity": format!("{:?}", s.sensitivity),
                "version": s.version,
                "warning": "Plaintext withheld. Use vault.use for proxy operations or vault.reveal (requires Operator Confirmation) for explicit access.",
            })
            .to_string(),
        )]))
    }

    /// List Secrets matching optional filter criteria. Returns public metadata
    /// only — no plaintext.
    #[tool(
        name = "vault.list",
        description = "List Secrets matching filter criteria. Returns public metadata only (no plaintext). Supports category, tag, name-pattern, expiry, sensitivity, and FTS5 filters."
    )]
    pub async fn vault_list(
        &self,
        Parameters(input): Parameters<VaultListInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let resp = self
            .client
            .list_secrets(
                namespace_id,
                &ListSecretsParams {
                    category: input.category,
                    sensitivity: None,
                    tags: None,
                    name_pattern: input.name_pattern,
                    expires_before: None,
                    fts_query: input.fts_query,
                    limit: input.limit.unwrap_or(50),
                    cursor: None,
                },
            )
            .await
            .map_err(client_error_to_mcp)?;

        let items: Vec<_> = resp
            .items
            .iter()
            .map(|s| {
                json!({
                    "handle": s.handle.to_string(),
                    "name": s.name,
                    "category": s.category,
                    "sensitivity": format!("{:?}", s.sensitivity),
                    "version": s.version,
                    "expose": s.expose,
                    "expires_at": s.expires_at.map(|t| t.to_rfc3339()),
                })
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            json!({"items": items, "total": resp.total}).to_string(),
        )]))
    }

    /// Return full public metadata for a single Secret including its
    /// `schema_id` field.
    #[tool(
        name = "vault.describe",
        description = "Return full public metadata for a single Secret, including schema_id. Does not return plaintext."
    )]
    pub async fn vault_describe(
        &self,
        Parameters(input): Parameters<VaultDescribeInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let s = self
            .client
            .get_secret(namespace_id, &encode_handle(&handle))
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "handle": s.handle.to_string(),
                "name": s.name,
                "category": s.category,
                "sensitivity": format!("{:?}", s.sensitivity),
                "version": s.version,
                "schema_id": s.schema_id,
                "description": s.description,
                "expose": s.expose,
                "created_at": s.created_at.to_rfc3339(),
                "updated_at": s.updated_at.map(|t| t.to_rfc3339()),
                "expires_at": s.expires_at.map(|t| t.to_rfc3339()),
                "expiry_warning": s.expiry_warning,
                "tags": s.tags.iter().map(|t| json!({"key": t.key, "value": t.value})).collect::<Vec<_>>(),
            })
            .to_string(),
        )]))
    }

    /// Replace the active value of a Secret while retaining prior versions up
    /// to the Namespace Policy `retain_count`.
    #[tool(
        name = "vault.rotate",
        description = "Replace the active value of a Secret, retaining prior versions per Namespace Policy. Preferred over delete+put for Secret updates — preserves version history and the handle URI."
    )]
    pub async fn vault_rotate(
        &self,
        Parameters(input): Parameters<VaultRotateInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let resp = self
            .client
            .rotate_secret(
                namespace_id,
                &encode_handle(&handle),
                RotateSecretRequest {
                    new_value: input.new_value,
                    value_format: merkle_companion_client::dto::ValueFormatDto::Utf8,
                    purpose: input.purpose,
                },
            )
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "handle": resp.handle.to_string(),
                "version": resp.version,
                "rotated_at": resp.rotated_at.to_rfc3339(),
                "versions_retained": resp.versions_retained,
            })
            .to_string(),
        )]))
    }

    /// Permanently delete a Secret and all its versions. Irreversible.
    #[tool(
        name = "vault.delete",
        description = "Permanently delete a Secret and all its versions. This operation is irreversible. Recorded in the audit log."
    )]
    pub async fn vault_delete(
        &self,
        Parameters(input): Parameters<VaultDeleteInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let resp = self
            .client
            .delete_secret(
                namespace_id,
                &encode_handle(&handle),
                DeleteSecretRequest {
                    purpose: input.purpose,
                    operator_confirmation: OperatorConfirmationDeleteSecret {
                        slash_command: true,
                        oob_ack: false,
                    },
                },
            )
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "deleted": resp.deleted,
                "versions_removed": resp.versions_removed,
            })
            .to_string(),
        )]))
    }

    /// Free-text semantic search over public metadata using the FTS5 index.
    /// Returns ranked handles with a relevance score.
    #[tool(
        name = "vault.search",
        description = "Free-text semantic search over public metadata using the FTS5 index. Returns ranked handles with BM25 relevance scores (lower = more relevant)."
    )]
    pub async fn vault_search(
        &self,
        Parameters(input): Parameters<VaultSearchInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };
        let limit = input.limit.unwrap_or(10);

        let resp = self
            .client
            .list_secrets(
                namespace_id,
                &ListSecretsParams {
                    fts_query: Some(input.query),
                    limit,
                    category: None,
                    sensitivity: None,
                    tags: None,
                    name_pattern: None,
                    expires_before: None,
                    cursor: None,
                },
            )
            .await
            .map_err(client_error_to_mcp)?;

        let results: Vec<_> = resp
            .items
            .iter()
            .map(|s| {
                json!({
                    "handle": s.handle.to_string(),
                    "name": s.name,
                    "category": s.category,
                    "sensitivity": format!("{:?}", s.sensitivity),
                })
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            json!({"results": results, "count": results.len()}).to_string(),
        )]))
    }

    /// Return the version history of a Secret.
    #[tool(
        name = "vault.history",
        description = "Return the version history of a Secret. Shows creation, rotation, and deletion timestamps per version."
    )]
    pub async fn vault_history(
        &self,
        Parameters(input): Parameters<VaultHistoryInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };
        let limit = input.limit.unwrap_or(10) as usize;

        let resp = self
            .client
            .list_secret_versions(namespace_id, &encode_handle(&handle))
            .await
            .map_err(client_error_to_mcp)?;

        let versions: Vec<_> = resp
            .versions
            .iter()
            .take(limit)
            .map(|v| {
                json!({
                    "version": v.version,
                    "created_at": v.created_at.to_rfc3339(),
                    "rotated_at": v.rotated_at.map(|t| t.to_rfc3339()),
                    "deleted_at": v.deleted_at.map(|t| t.to_rfc3339()),
                    "size_bytes": v.size_bytes,
                })
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "handle": resp.handle.to_string(),
                "versions": versions,
            })
            .to_string(),
        )]))
    }
}
