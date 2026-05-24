//! `SshCopyCommand` — copy a file to/from a remote host using a vault SSH key.
//!
//! Calls [`ExternalServices::ssh_exec`] to run an `scp`-equivalent command on
//! the remote side. Audited with `op=ssh_copy`.

use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for SSH copy.
#[derive(Debug)]
pub struct SshCopyCommand {
    /// Namespace to audit under.
    pub namespace_id: NamespaceId,
    /// SSH target (`host:port`) for the connection.
    pub target: String,
    /// Source path (local or remote).
    pub source: String,
    /// Destination path (local or remote).
    pub destination: String,
    /// PEM-encoded SSH private key bytes.
    pub key_material: Vec<u8>,
}

/// Output of `SshCopyCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SshCopyOutput {
    /// Exit code returned by the remote copy command.
    pub exit_code: i32,
    /// Captured stderr bytes.
    pub stderr: Vec<u8>,
}

impl SshCopyCommand {
    /// Execute ssh-copy.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::External`] — SSH connection or command failed.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<SshCopyOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(target = %self.target, "ssh_copy: executing remote copy");

        let scp_cmd = format!("scp '{}' '{}'", self.source, self.destination);
        let result = ctx
            .external
            .ssh_exec(&self.target, &self.key_material, &scp_cmd)
            .await?;

        // Audit: op=ssh_copy.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::SshCopy,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        drop(log);
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!(exit_code = result.exit_code, "ssh_copy: complete");
        Ok(SshCopyOutput {
            exit_code: result.exit_code,
            stderr: result.stderr,
        })
    }
}
