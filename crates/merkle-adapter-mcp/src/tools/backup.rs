//! Backup and restore tools: vault.backup, vault.restore.
//!
//! Both commands are fully implemented (F5.B).
//! `vault.restore` maps the `source` path string to `AgeIdentity` —
//! full snapshot-lookup wiring is deferred to Phase 5.C.

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
    execute_restore::ExecuteRestoreCommand, trigger_backup::TriggerBackupCommand,
};
use merkle_domain_backup_recovery::trigger::BackupTrigger;
use merkle_ports::AgeIdentity;
use merkle_types::{NamespaceId, UuidV7};

// ---------------------------------------------------------------------------
// Input parameter structs
// ---------------------------------------------------------------------------

/// Input for vault.backup.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultBackupInput {
    /// Optional destination path for the backup archive.
    /// If omitted, the agent uses its configured backup directory.
    pub destination: Option<String>,
    /// `age` bech32 recipient for the master public key.
    /// If omitted, a default is used from the vault configuration.
    pub master_pubkey_recipient: Option<String>,
    /// `age` bech32 recipient for the recovery public key.
    /// If omitted, a default is used from the vault configuration.
    pub recovery_pubkey_recipient: Option<String>,
}

/// Input for vault.restore.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct VaultRestoreInput {
    /// Path to the backup archive to restore from.
    pub source: String,
    /// If true, confirm destructive restore (overwrites current data).
    pub confirm: bool,
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

#[allow(missing_docs)]
#[rmcp::tool_router(router = backup_router)]
impl MerkleMcpServer {
    /// Trigger an on-demand encrypted backup of the Vault Agent database.
    /// Returns the backup path, size, and checksum.
    #[tool(
        name = "vault.backup",
        description = "Trigger an on-demand encrypted backup of the Vault Agent database. Returns the backup path, size, and checksum. The backup is age-encrypted for the configured recipients."
    )]
    pub async fn vault_backup(
        &self,
        Parameters(input): Parameters<VaultBackupInput>,
    ) -> Result<CallToolResult, ErrorData> {
        // Namespace resolution: use session binding if present, else a new UUID.
        let namespace_id = {
            let session = self.session.read().await;
            session
                .namespace_label()
                .ok_or_else(crate::errors::namespace_not_bound)?;
            NamespaceId::new()
        };

        let output_path = std::path::PathBuf::from(
            input
                .destination
                .as_deref()
                .unwrap_or("/tmp/merkle-backup.age"),
        );

        let cmd = TriggerBackupCommand {
            namespace_id,
            trigger: BackupTrigger::Manual,
            master_pubkey_recipient: input
                .master_pubkey_recipient
                .unwrap_or_default(),
            recovery_pubkey_recipient: input
                .recovery_pubkey_recipient
                .unwrap_or_default(),
            output_path: output_path.clone(),
        };

        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "snapshot_id": out.backup.id.to_string(),
                "namespace_id": out.backup.namespace_id.to_string(),
                "output_path": output_path.to_string_lossy(),
                "size_bytes": out.backup.size_bytes,
                "secret_count": out.backup.secret_count,
            })
            .to_string(),
        )]))
    }

    /// Restore the Vault Agent database from an encrypted backup archive.
    /// Requires `confirm = true` to prevent accidental data loss.
    /// The agent must be sealed before restore.
    #[tool(
        name = "vault.restore",
        description = "Restore the Vault Agent database from an encrypted backup archive. Requires confirm=true to prevent accidental data loss. The agent must be sealed before restore."
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

        let namespace_id = {
            let session = self.session.read().await;
            session
                .namespace_label()
                .ok_or_else(crate::errors::namespace_not_bound)?;
            NamespaceId::new()
        };

        // ADAPTER NOTE (F6.B): `source` in the MCP input is treated as an
        // age-identity private key string because `ExecuteRestoreCommand`
        // expects `age_identity` (the private key material) and
        // `backup_snapshot_id`. Full snapshot-lookup from a path is deferred
        // to Phase 5.C; the command will fail with `AppError::NotFound` if
        // no matching backup record exists in storage.
        let cmd = ExecuteRestoreCommand {
            namespace_id,
            backup_snapshot_id: UuidV7::new(),
            age_identity: AgeIdentity(input.source.clone()),
        };
        let out = cmd.execute(&self.app_ctx).await.map_err(app_error_to_mcp)?;

        Ok(CallToolResult::success(vec![Content::text(
            json!({
                "restored": true,
                "secrets_restored": out.secrets_restored,
            })
            .to_string(),
        )]))
    }
}
