//! `SpawnCommandCommand` — spawn a subprocess with a secret injected as an env var.
//!
//! Resolves the secret by handle, decrypts the private blob, injects the
//! plaintext into the subprocess environment under the specified `env_var` name,
//! awaits the child process, and returns stdout/stderr/exit-code. The
//! plaintext is never written to disk. Audited with `op=spawn`.
//!
//! Fail-closed executable policy: only an allowlisted basename may run.

use std::collections::HashSet;
use std::process::Stdio;
use std::sync::LazyLock;

use crate::{AppContext, AppError};
use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId};
use tokio::process::Command;
use tracing::info;

/// Closed allowlist of executable basenames permitted for spawn (fail-closed).
static ALLOWED_BINARIES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "curl", "wget", "env", "printenv", "echo", "true", "false", "cat", "head", "tail",
        "jq", "base64", "sha256sum", "openssl", "git", "ssh", "scp", "rsync",
    ])
});

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
    /// - [`AppError::PolicyDenied`] — binary not allowlisted or bad env name.
    /// - [`AppError::NotFound`] — secret missing.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<SpawnCommandOutput, AppError> {
        ctx.require_unsealed().await?;

        if self.argv.is_empty() {
            return Err(AppError::InvalidInput("argv must not be empty".into()));
        }
        if self.env_var.trim().is_empty()
            || !self
                .env_var
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(AppError::InvalidInput(
                "env_var must be a non-empty ASCII identifier".into(),
            ));
        }

        let program = std::path::Path::new(&self.argv[0])
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if !ALLOWED_BINARIES.contains(program) {
            let hmac_key = ctx.require_hmac_key().await?;
            let params = merkle_domain_audit_compliance::AppendParams::new(
                AuditOp::Spawn,
                AuditOutcome::Deny,
                self.namespace_id,
            )
            .handle(self.handle.clone())
            .denial_reason("spawn_binary_not_allowlisted")
            .caller_program("merkle-agent");
            crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;
            return Err(AppError::PolicyDenied(format!(
                "spawn binary '{program}' is not allowlisted"
            )));
        }

        let secret = ctx
            .storage
            .get_secret_by_handle(&self.handle)
            .await?
            .ok_or(AppError::NotFound)?;
        let blob = secret
            .versions()
            .iter()
            .find(|v| v.is_active())
            .ok_or(AppError::NotFound)?
            .blob
            .clone();
        let mut cipher_with_tag = blob.ciphertext.clone();
        cipher_with_tag.extend_from_slice(&blob.aead_tag);
        let plaintext = ctx.crypto.aead_decrypt(
            &self.dek_bytes,
            &blob.nonce,
            &cipher_with_tag,
            &blob.associated_data,
        )?;

        info!(program = %program, "spawn: launching allowlisted process");

        // Env values are OS strings; inject as lossy UTF-8 (secrets often text).
        let env_value = String::from_utf8_lossy(&plaintext).into_owned();
        drop(plaintext);

        let output = Command::new(&self.argv[0])
            .args(&self.argv[1..])
            .env(&self.env_var, &env_value)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|e| AppError::Domain(format!("failed to spawn process: {e}")))?;

        drop(env_value);

        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Spawn,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .handle(self.handle.clone())
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        Ok(SpawnCommandOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code().unwrap_or(-1),
        })
    }
}
