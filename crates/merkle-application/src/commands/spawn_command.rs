//! `SpawnCommandCommand` — spawn a subprocess with a secret injected as an env var.
//!
//! Resolves the secret by handle, decrypts the private blob, injects the
//! plaintext into the subprocess environment under the specified `env_var` name,
//! awaits the child process, and returns stdout/stderr/exit-code. The
//! plaintext is never written to disk. Audited with `op=spawn`.

use crate::{AppContext, AppError};
use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId};

/// Input for spawning a command with secret injection.
#[derive(Debug)]
pub struct SpawnCommandCommand {
    /// Namespace owning the secret.
    pub namespace_id: NamespaceId,
    /// Secret handle to inject as an environment variable.
    pub handle: Handle,
    /// Name of the environment variable to inject the plaintext into.
    pub env_var: String,
    /// 32-byte namespace DEK for decryption.
    pub dek_bytes: [u8; 32],
    /// Command and arguments to spawn (`argv[0]` is the program name).
    pub argv: Vec<String>,
}

/// Output of `SpawnCommandCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SpawnCommandOutput {
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
    /// Exit code.
    pub exit_code: i32,
}

impl SpawnCommandCommand {
    /// Execute spawn-command.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::PolicyDenied`] — the capability is disabled pending
    ///   process-execution security controls.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<SpawnCommandOutput, AppError> {
        ctx.require_unsealed().await?;

        // No process is launched until a fail-closed executable policy and a
        // non-exfiltrating output contract exist. Keeping this guard in the
        // use case closes in-process bypasses of the socket endpoint.
        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Spawn,
            AuditOutcome::Deny,
            self.namespace_id,
        )
        .handle(self.handle.clone())
        .denial_reason("capability_disabled_pending_security_controls")
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;
        Err(AppError::PolicyDenied(
            "spawn_capability_disabled_pending_security_controls".into(),
        ))
    }
}
