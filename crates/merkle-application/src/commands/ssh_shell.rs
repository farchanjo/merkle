//! `SshShellCommand` — buffered interactive SSH shell session.
//!
//! Executes a shell invocation via [`ExternalServices::ssh_exec`] using an
//! interactive shell (`/bin/sh -l`). Output is buffered and returned. For
//! true interactive PTY sessions Phase 6 is required. Audited with `op=ssh_exec`
//! (no dedicated ssh_shell op in the closed enum).

use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for SSH shell.
#[derive(Debug)]
pub struct SshShellCommand {
    /// Namespace to audit under.
    pub namespace_id: NamespaceId,
    /// Host and port (`host:port`).
    pub target: String,
    /// PEM-encoded SSH private key bytes.
    pub key_material: Vec<u8>,
    /// Optional command to run in the remote shell. `None` opens `/bin/sh -l`.
    pub command: Option<String>,
}

/// Output of `SshShellCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SshShellOutput {
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
    /// Exit code.
    pub exit_code: i32,
}

impl SshShellCommand {
    /// Execute ssh-shell (buffered).
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::External`] — SSH connection or command failed.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<SshShellOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(target = %self.target, "ssh_shell: executing remote shell");

        let shell_cmd = self.command.as_deref().unwrap_or("/bin/sh -l");

        let result = ctx
            .external
            .ssh_exec(&self.target, &self.key_material, shell_cmd)
            .await?;

        // Audit: op=ssh_exec (no dedicated shell op in the closed enum).
        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::SshExec,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(exit_code = result.exit_code, "ssh_shell: complete");
        Ok(SshShellOutput {
            stdout: result.stdout,
            stderr: result.stderr,
            exit_code: result.exit_code,
        })
    }
}
