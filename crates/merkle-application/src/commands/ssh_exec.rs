//! `SshExecCommand` — remote SSH command execution via `ExternalServices`.
//!
//! Delegates to [`ExternalServices::ssh_exec`] and appends an `op=ssh_exec`
//! audit entry on success.

use merkle_ports::SshExecOutput;
use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for SSH exec.
#[derive(Debug)]
pub struct SshExecCommand {
    /// Namespace to audit under.
    pub namespace_id: NamespaceId,
    /// Host and port (`host:port`).
    pub target: String,
    /// PEM-encoded SSH private key bytes.
    pub key_material: Vec<u8>,
    /// Command to execute on the remote host.
    pub command: String,
}

/// Output of `SshExecCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SshExecOutput2 {
    /// Captured stdout, stderr, and exit code.
    pub result: SshExecOutput,
}

impl SshExecCommand {
    /// Execute ssh-exec via the external services port.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::External`] — SSH connection or command failed.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<SshExecOutput2, AppError> {
        ctx.require_unsealed().await?;

        info!(target = %self.target, command = %self.command, "ssh_exec: executing remote command");

        let result = ctx
            .external
            .ssh_exec(&self.target, &self.key_material, &self.command)
            .await?;

        // Audit: op=ssh_exec.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::SshExec,
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

        info!(exit_code = result.exit_code, "ssh_exec: complete");
        Ok(SshExecOutput2 { result })
    }
}
