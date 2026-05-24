//! `SpawnCommandCommand` — spawn a subprocess with a secret injected as an env var.
//!
//! Resolves the secret by handle, decrypts the private blob, injects the
//! plaintext into the subprocess environment under the specified `env_var` name,
//! awaits the child process, and returns stdout/stderr/exit-code. The
//! plaintext is never written to disk. Audited with `op=spawn`.

use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId};
use tokio::process::Command;
use tracing::info;

use crate::{AppContext, AppError};

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
    /// - [`AppError::NotFound`] — secret not found for handle.
    /// - [`AppError::Crypto`] — AEAD decryption failed.
    /// - [`AppError::InvalidInput`] — empty `argv`.
    /// - [`AppError::Domain`] — subprocess failed to start or was killed.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<SpawnCommandOutput, AppError> {
        ctx.require_unsealed().await?;

        if self.argv.is_empty() {
            return Err(AppError::InvalidInput("argv must not be empty".into()));
        }

        info!(handle = %self.handle, env_var = %self.env_var, "spawn_command: resolving secret");

        // Decrypt the secret.
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

        // Convert plaintext to a UTF-8 string for env injection.
        let secret_val = String::from_utf8_lossy(&plaintext).into_owned();

        let program = &self.argv[0];
        let args = &self.argv[1..];

        let output = Command::new(program)
            .args(args)
            .env(&self.env_var, &secret_val)
            .output()
            .await
            .map_err(|e| AppError::Domain(format!("spawn_command: failed to spawn: {e}")))?;

        let exit_code = output.status.code().unwrap_or(-1);

        // Audit: op=spawn.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Spawn,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .handle(self.handle.clone())
        .sensitivity(secret.sensitivity)
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        drop(log);
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!(exit_code = exit_code, "spawn_command: process complete");
        Ok(SpawnCommandOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code,
        })
    }
}
