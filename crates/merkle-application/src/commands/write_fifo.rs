//! `WriteFifoCommand` — materialize a secret to a named pipe (FIFO).
//!
//! Creates a FIFO at a random path under the system temp directory, spawns a
//! background task to write the plaintext exactly once when a reader connects,
//! and returns an opaque token identifying the FIFO. The FIFO is removed after
//! the first write or on session close. Audited with `op=write_tempfile`.
//!
//! # Platform
//!
//! FIFO creation requires a UNIX-like OS. On non-UNIX platforms this command
//! returns [`AppError::NotImplemented`].

use std::path::PathBuf;

use merkle_domain_access_mediation::fifo::Fifo;
use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId, Rfc3339Timestamp};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for writing to a named pipe.
#[derive(Debug)]
pub struct WriteFifoCommand {
    /// Namespace owning the secret.
    pub namespace_id: NamespaceId,
    /// Secret handle to materialize.
    pub handle: Handle,
    /// 32-byte namespace DEK for decryption.
    pub dek_bytes: [u8; 32],
}

/// Output of `WriteFifoCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WriteFifoOutput {
    /// Opaque token — the only identifier returned to the MCP transport.
    pub opaque_token: String,
    /// RFC 3339 session-lifetime expiration timestamp.
    pub expires_at: Rfc3339Timestamp,
}

impl WriteFifoCommand {
    /// Execute write-fifo.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::NotFound`] — secret not found for handle.
    /// - [`AppError::Crypto`] — AEAD decryption failed.
    /// - [`AppError::Domain`] — FIFO creation or write failed.
    /// - [`AppError::Storage`] — audit write failed.
    /// - [`AppError::NotImplemented`] — non-UNIX platform.
    pub async fn execute(&self, ctx: &AppContext) -> Result<WriteFifoOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(handle = %self.handle, "write_fifo: resolving secret");

        // Load and decrypt the active secret version.
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

        // Generate opaque token and build FIFO path.
        let token_bytes = ctx.crypto.random_bytes_32();
        let opaque_token = hex::encode(token_bytes);
        let fifo_path = build_fifo_path(&opaque_token);

        // Create the named pipe (UNIX only).
        create_fifo(&fifo_path)?;

        // Spawn a task that opens the FIFO for writing, writes plaintext exactly
        // once (blocking until a reader connects), then removes the FIFO.
        {
            let fifo_path_clone = fifo_path.clone();
            tokio::task::spawn_blocking(move || {
                use std::io::Write as _;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&fifo_path_clone)
                {
                    let _ = f.write_all(&plaintext);
                }
                let _ = std::fs::remove_file(&fifo_path_clone);
            });
        }

        let expires_at = Rfc3339Timestamp::now();

        // Domain entity (path server-side only — never crosses MCP boundary).
        let _fifo = Fifo {
            opaque_token: opaque_token.clone(),
            real_path_redacted: fifo_path,
            consumed: false,
        };

        // Audit: op=write_tempfile (closest available op in the closed enum).
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::WriteTempfile,
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

        info!(handle = %self.handle, "write_fifo: FIFO created and writer task spawned");
        Ok(WriteFifoOutput {
            opaque_token,
            expires_at,
        })
    }
}

/// Build the FIFO path under the system temp directory.
fn build_fifo_path(opaque_token: &str) -> PathBuf {
    std::env::temp_dir().join(format!("merkle_{opaque_token}.fifo"))
}

/// Create a UNIX named pipe (mkfifo) at the given path.
fn create_fifo(path: &PathBuf) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        // Use the `mkfifo` command as a subprocess — avoids adding libc as a
        // direct dependency while remaining SAFETY-comment-free in the application
        // layer. The path is known-safe (temp dir + hex token).
        let status = std::process::Command::new("mkfifo")
            .arg("--mode=0600")
            .arg(path)
            .status()
            .map_err(|e| AppError::Domain(format!("write_fifo: mkfifo exec failed: {e}")))?;
        if status.success() {
            Ok(())
        } else {
            Err(AppError::Domain(format!(
                "write_fifo: mkfifo returned non-zero: {:?}",
                status.code()
            )))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(AppError::NotImplemented)
    }
}
