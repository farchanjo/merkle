//! Secret CRUD tools:
//! vault.put, vault.get, vault.list, vault.describe,
//! vault.rotate, vault.rollback, vault.delete, vault.search, vault.history.
//!
//! All operations are forwarded to the Vault Agent Companion Socket via
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
use uuid::Uuid;

use crate::{MerkleMcpServer, errors::client_error_to_mcp};
use merkle_companion_client::dto::{
    DeleteSecretRequest, ListSecretsParams, OperatorConfirmation, OperatorConfirmationDeleteSecret,
    PutSecretRequest, RollbackSecretRequest, RotateSecretRequest, TagDto, ValueFormatDto,
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
    pub value: String,
    /// Optional custom CUE schema reference; omit to use the built-in schema.
    pub schema_id: Option<String>,
    /// Optional tags to associate with the Secret.
    pub tags: Option<Vec<String>>,
    /// Sensitivity level: low | medium | high.
    pub sensitivity: Option<String>,
    /// Optional public description (safe for LLM transcript; never put credentials here).
    pub description: Option<String>,
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
    pub new_value: String,
    /// Human-readable reason; recorded in the audit log.
    pub purpose: String,
}

/// Input for vault.rollback — restore a historical version as a new active version.
///
/// Note: there is deliberately no `operator_confirmation` argument. Confirmation
/// is sourced from the client-injected request `_meta` (MERK-001).
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultRollbackInput {
    /// Handle URI of the Secret to roll back.
    pub handle: String,
    /// Historical version number to restore (copied into a new version).
    pub target_version: u32,
    /// Human-readable reason; recorded in the audit log.
    pub purpose: String,
}

/// Input for vault.delete — permanently delete a Secret and all its versions.
///
/// Note: there is deliberately no `operator_confirmation` argument. The
/// confirmation for this irreversible operation is sourced from the
/// client-injected request `_meta` (see [`crate::OPERATOR_CONFIRMATION_META_KEY`]),
/// never from a tool argument the model controls (MERK-001).
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
    /// Natural-language or keyword query (FTS5 MATCH expression).
    pub query: String,
    /// Maximum results per page (default 10, max 50).
    pub limit: Option<u32>,
    /// Zero-based page offset for ranked result pagination.
    pub offset: Option<u32>,
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

/// Convert MCP tag strings into transport [`TagDto`]s.
///
/// Each tag is expressed as `key:value`. A bare token without a `:` is mapped
/// to a tag whose key and value are both the token, so it survives the daemon's
/// `key`/`value` tag validation. Without this conversion the tags supplied to
/// `vault.put` were silently dropped (BUG-10).
fn tag_strings_to_dto(tags: Vec<String>) -> Vec<TagDto> {
    tags.into_iter()
        .map(|t| match t.split_once(':') {
            Some((key, value)) => TagDto {
                key: key.to_owned(),
                value: value.to_owned(),
            },
            None => TagDto {
                key: t.clone(),
                value: t,
            },
        })
        .collect()
}

/// Build the daemon [`PutSecretRequest`] from the tool input, forwarding the
/// `tags` and `sensitivity` fields that were previously dropped (BUG-10).
fn put_request_from_input(input: VaultPutInput) -> PutSecretRequest {
    PutSecretRequest {
        name: input.name,
        category: input.category,
        value: input.value,
        value_format: ValueFormatDto::Utf8,
        schema_id: input.schema_id,
        tags: input.tags.map(tag_strings_to_dto).unwrap_or_default(),
        sensitivity: input.sensitivity.as_deref().and_then(|s| s.parse().ok()),
        description: input.description,
        expose: input.expose.unwrap_or(false),
        expires_at: None,
        force: false,
    }
}

/// Build the daemon [`ListSecretsParams`] from the tool input, forwarding the
/// `tags`, `sensitivity`, and `expires_before` filters that were previously
/// dropped (BUG-11).
fn list_params_from_input(input: VaultListInput) -> ListSecretsParams {
    ListSecretsParams {
        category: input.category,
        sensitivity: input.sensitivity.as_deref().and_then(|s| s.parse().ok()),
        tags: input.tags.filter(|t| !t.is_empty()).map(|t| t.join(",")),
        name_pattern: input.name_pattern,
        expires_before: input.expires_before.as_deref().and_then(|s| s.parse().ok()),
        fts_query: input.fts_query,
        limit: input.limit.unwrap_or(50),
        cursor: None,
        offset: 0,
    }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[allow(
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
            .put_secret(namespace_id, put_request_from_input(input))
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
            .list_secrets(namespace_id, &list_params_from_input(input))
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

    /// Roll a Secret back to a retained historical version by appending a new
    /// version that copies the target blob (immutable history).
    ///
    /// Gated on operator confirmation from client-injected request `_meta`
    /// (set by `/merkle-rollback`) — not a model-controlled tool argument
    /// (MERK-001).
    #[tool(
        name = "vault.rollback",
        description = "Roll a Secret back to a retained historical version by copying its blob into a new active version (immutable history). Requires operator confirmation via the /merkle-rollback slash command (injected into request _meta by the client, not a tool argument)."
    )]
    pub async fn vault_rollback(
        &self,
        Parameters(input): Parameters<VaultRollbackInput>,
        meta: rmcp::model::Meta,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;

        if !crate::operator_confirmation_from_meta(&meta) {
            return Err(ErrorData::invalid_params(
                "vault.rollback requires an operator confirmation issued via the \
                 /merkle-rollback slash command; refusing to roll back autonomously",
                None,
            ));
        }

        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };

        let resp = self
            .client
            .rollback_secret(
                namespace_id,
                &encode_handle(&handle),
                RollbackSecretRequest {
                    target_version: input.target_version,
                    operator_confirmation: OperatorConfirmation {
                        slash_command: true,
                        oob_ack: false,
                        oob_channel: None,
                    },
                    purpose: Some(input.purpose),
                },
            )
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "handle": resp.handle.to_string(),
                "active_version": resp.active_version,
                "rolled_back_at": resp.rolled_back_at.to_rfc3339(),
            })
            .to_string(),
        )]))
    }

    /// Permanently delete a Secret and all its versions. Irreversible.
    ///
    /// Gated on an operator confirmation that the client injects into the
    /// request `_meta` when a `/merkle-delete` slash command is issued by the
    /// human operator — the model cannot supply it through tool arguments
    /// (MERK-001).
    #[tool(
        name = "vault.delete",
        description = "Permanently delete a Secret and all its versions. Irreversible. Requires an operator confirmation issued via the /merkle-delete slash command (injected into request _meta by the client, not a tool argument). Recorded in the audit log."
    )]
    pub async fn vault_delete(
        &self,
        Parameters(input): Parameters<VaultDeleteInput>,
        meta: rmcp::model::Meta,
    ) -> Result<CallToolResult, ErrorData> {
        let handle = parse_handle(&input.handle)?;

        // Irreversible deletion must never be initiated autonomously by the
        // model. The confirmation provenance is read from the client-injected
        // request `_meta` (set by the /merkle-delete slash command), not from a
        // model-controlled tool argument (MERK-001). Without it the call is
        // rejected before any state change.
        if !crate::operator_confirmation_from_meta(&meta) {
            return Err(ErrorData::invalid_params(
                "vault.delete is irreversible and requires an operator confirmation \
                 issued via the /merkle-delete slash command; refusing to delete \
                 autonomously",
                None,
            ));
        }

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
                        // True by construction: the early return above rejects any
                        // call lacking client-injected `_meta` provenance.
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
    ///
    /// Returns ranked results with BM25 relevance scores. SQLite FTS5 `bm25()`
    /// returns negative values — **more negative = more relevant**. Results are
    /// ordered best-first. Each result includes `score`, `bm25_rank` (1-based,
    /// page-local), and `highlights` (per-field snippets with `<b>` markers).
    ///
    /// Weight vector: name=10.0, tags=5.0, description=3.0, category=2.0,
    /// namespace_label=1.0. A name match strongly dominates a description match.
    #[tool(
        name = "vault.search",
        description = "Weighted BM25 full-text search over public metadata (name, tags, description, category, namespace_label). Returns ranked results with score (more negative = more relevant), bm25_rank (1-based, page-local), and per-field highlights. Paginate with limit + offset."
    )]
    pub async fn vault_search(
        &self,
        Parameters(input): Parameters<VaultSearchInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let namespace_id = {
            let session = self.session.read().await;
            resolve_namespace(&session)?
        };
        let limit = input.limit.unwrap_or(10).clamp(1, 50);
        let offset = input.offset.unwrap_or(0);

        let resp = self
            .client
            .list_secrets(
                namespace_id,
                &ListSecretsParams {
                    fts_query: Some(input.query),
                    limit,
                    offset,
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

        // Ranked mode: server populates ranked_items when fts_query is set.
        let results: Vec<_> = resp
            .ranked_items
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|rs| {
                json!({
                    "handle": rs.secret.handle.to_string(),
                    "name": rs.secret.name,
                    "category": rs.secret.category,
                    "sensitivity": format!("{:?}", rs.secret.sensitivity),
                    "score": rs.score,
                    "bm25_rank": rs.bm25_rank,
                    "highlights": rs.highlights.iter().map(|h| json!({
                        "field": h.field,
                        "snippet": h.snippet,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "results": results,
                "count": results.len(),
                "total": resp.total,
                "has_more": resp.has_more.unwrap_or(false),
                "offset": offset,
            })
            .to_string(),
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

#[cfg(test)]
mod tests {
    use super::{
        VaultDeleteInput, VaultListInput, VaultPutInput, VaultRollbackInput,
        list_params_from_input, put_request_from_input,
    };
    use merkle_types::Sensitivity;

    /// MERK-001: `operator_confirmation` is no longer a delete input field, so a
    /// model that smuggles it into the tool `arguments` cannot authorize an
    /// irreversible delete — the flag is dropped at parse time and provenance is
    /// taken from the client-injected request `_meta` instead.
    #[test]
    fn model_supplied_operator_confirmation_is_not_a_delete_input_field() {
        let json = serde_json::json!({
            "handle": "vault://default/token/api",
            "purpose": "cleanup",
            "operator_confirmation": true
        });
        let input: VaultDeleteInput = serde_json::from_value(json).expect("parse");
        assert_eq!(input.handle, "vault://default/token/api");
        assert_eq!(input.purpose, "cleanup");
    }

    /// MERK-001: same provenance rule for rollback — no tool-arg confirmation.
    #[test]
    fn model_supplied_operator_confirmation_is_not_a_rollback_input_field() {
        let json = serde_json::json!({
            "handle": "vault://default/token/api",
            "target_version": 2,
            "purpose": "undo bad rotate",
            "operator_confirmation": true
        });
        let input: VaultRollbackInput = serde_json::from_value(json).expect("parse");
        assert_eq!(input.handle, "vault://default/token/api");
        assert_eq!(input.target_version, 2);
        assert_eq!(input.purpose, "undo bad rotate");
    }

    /// BUG-10: vault.put must forward `tags` and `sensitivity` to the daemon.
    #[test]
    fn put_request_forwards_tags_and_sensitivity() {
        let input = VaultPutInput {
            category: "token".into(),
            name: "api".into(),
            value: "v".into(),
            schema_id: None,
            tags: Some(vec!["env:prod".into(), "team:core".into()]),
            sensitivity: Some("high".into()),
            description: Some("prod API token".into()),
            expose: None,
        };

        let req = put_request_from_input(input);

        assert_eq!(req.tags.len(), 2, "tags must be forwarded, not dropped");
        assert_eq!(req.tags[0].key, "env");
        assert_eq!(req.tags[0].value, "prod");
        assert_eq!(req.tags[1].key, "team");
        assert_eq!(req.tags[1].value, "core");
        assert_eq!(req.sensitivity, Some(Sensitivity::High));
        assert_eq!(req.description.as_deref(), Some("prod API token"));
    }

    /// BUG-11: vault.list must forward `tags`, `sensitivity`, and
    /// `expires_before` filters to the daemon.
    #[test]
    fn list_params_forward_dropped_filters() {
        let input = VaultListInput {
            category: Some("ssh".into()),
            tags: Some(vec!["env:prod".into(), "team:core".into()]),
            name_pattern: None,
            expires_before: Some("2030-01-01T00:00:00Z".into()),
            sensitivity: Some("medium".into()),
            fts_query: None,
            limit: None,
        };

        let params = list_params_from_input(input);

        assert_eq!(params.tags.as_deref(), Some("env:prod,team:core"));
        assert_eq!(params.sensitivity, Some(Sensitivity::Medium));
        assert!(
            params.expires_before.is_some(),
            "expires_before must be parsed and forwarded"
        );
        assert_eq!(params.category.as_deref(), Some("ssh"));
    }

    /// Empty tag list must not produce an empty `tags=` filter string.
    #[test]
    fn list_params_skip_empty_tags() {
        let input = VaultListInput {
            tags: Some(vec![]),
            ..VaultListInput::default()
        };
        let params = list_params_from_input(input);
        assert!(params.tags.is_none());
    }
}
