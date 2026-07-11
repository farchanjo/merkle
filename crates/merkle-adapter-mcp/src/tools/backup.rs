//! Backup and restore tools: vault_backup, vault_restore.
//!
//! Both commands are forwarded to the Vault Agent Companion Socket.
//! `vault_restore` is a two-step flow: create a restore plan first, then
//! execute it with operator confirmation.

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
use merkle_companion_client::dto::{
    CreateRestorePlanRequest, ExecuteRestoreRequest, OperatorConfirmationDeleteSecret, RestoreMode,
    TriggerBackupRequest,
};

// ---------------------------------------------------------------------------
// Input parameter structs
// ---------------------------------------------------------------------------

/// Input for vault_backup.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultBackupInput {
    /// Optional human-readable note for this backup snapshot.
    pub note: Option<String>,
}

/// Input for vault_restore.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultRestoreInput {
    /// Filename (not full path) of the backup snapshot to restore from.
    pub snapshot_filename: String,
    /// Restore strategy: overwrite | merge | newest_wins.
    pub mode: Option<String>,
    /// If true, confirm destructive restore (overwrites current data).
    pub confirm: bool,
    /// Optional path to a recovery key file for age-encrypted snapshots.
    pub recovery_key_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Tool group marker type
// ---------------------------------------------------------------------------

/// Marker struct for the backup tool group.
pub struct BackupTools;

impl BackupTools {
    /// Build a `ToolRouter` containing all backup tools.
    #[must_use]
    pub fn router() -> ToolRouter<MerkleMcpServer> {
        MerkleMcpServer::backup_router()
    }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[allow(
    missing_docs,
    reason = "rmcp proc-macro generates the associated fn; doc lives on the #[tool] description attribute"
)]
#[rmcp::tool_router(router = backup_router)]
impl MerkleMcpServer {
    /// Trigger an on-demand encrypted backup of the Vault Agent database.
    /// Returns snapshot metadata. The backup is age-encrypted for the
    /// configured recipients.
    #[tool(
        name = "vault_backup",
        description = "Trigger an on-demand encrypted backup of the Vault Agent database. Returns snapshot metadata (filename, size, secret count). The backup is age-encrypted."
    )]
    pub async fn vault_backup(
        &self,
        Parameters(input): Parameters<VaultBackupInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let snap = self
            .client
            .trigger_backup(TriggerBackupRequest { note: input.note })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "filename": snap.filename,
                "created_at": snap.created_at.to_rfc3339(),
                "size_bytes": snap.size_bytes,
                "namespace_count": snap.namespace_count,
                "secret_count": snap.secret_count,
                "trigger": snap.trigger.as_ref().map(|t| format!("{t:?}")),
            })
            .to_string(),
        )]))
    }

    /// Restore the Vault Agent database from an encrypted backup snapshot.
    ///
    /// Requires `confirm = true` to prevent accidental data loss. The flow is
    /// two-step: this tool calls `POST /v1/backup/restore-plan` to validate the
    /// snapshot and generate a preview plan, then immediately calls
    /// `POST /v1/backup/restore` to execute it. The plan ID and confirmation
    /// are passed automatically; the caller only needs to supply the snapshot
    /// filename and set `confirm = true`.
    #[tool(
        name = "vault_restore",
        description = "Restore from an encrypted backup snapshot. Requires confirm=true. Two-step: validates plan then executes restore atomically."
    )]
    pub async fn vault_restore(
        &self,
        Parameters(input): Parameters<VaultRestoreInput>,
    ) -> Result<CallToolResult, ErrorData> {
        if !input.confirm {
            return Err(ErrorData::invalid_params(
                "confirm must be true to execute a destructive restore",
                None,
            ));
        }

        let mode = match input.mode.as_deref().unwrap_or("overwrite") {
            "merge" => RestoreMode::Merge,
            "newest_wins" => RestoreMode::NewestWins,
            _ => RestoreMode::Overwrite,
        };

        // Step 1: create restore plan.
        let plan = self
            .client
            .create_restore_plan(CreateRestorePlanRequest {
                snapshot_filename: input.snapshot_filename.clone(),
                mode,
                recovery_key_path: input.recovery_key_path,
            })
            .await
            .map_err(client_error_to_mcp)?;

        // Step 2: execute restore.
        let result = self
            .client
            .execute_restore(ExecuteRestoreRequest {
                plan_id: plan.plan_id.clone(),
                operator_confirmation: OperatorConfirmationDeleteSecret {
                    slash_command: true,
                    oob_ack: false,
                },
            })
            .await
            .map_err(client_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "restored": result.restored,
                "secrets_restored": result.secrets_restored,
                "namespaces_restored": result.namespaces_restored,
                "restored_at": result.restored_at.map(|t| t.to_rfc3339()),
                "plan_id": plan.plan_id,
                "snapshot_filename": input.snapshot_filename,
                "conflicts": plan.conflicts.len(),
            })
            .to_string(),
        )]))
    }
}
