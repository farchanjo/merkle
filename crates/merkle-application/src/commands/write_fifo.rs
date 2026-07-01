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
use zeroize::Zeroizing;

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
    /// Opaque single-use authorization token issued by `UseTokenCommand`.
    ///
    /// Validated and consumed before the FIFO is created and any plaintext is
    /// materialized; a missing, expired, replayed, or handle-mismatched token
    /// rejects the request.
    pub use_token: String,
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

        // Enforce the single-use + 60s-TTL use-token BEFORE the FIFO is created
        // and any plaintext is produced: reject unknown / expired / replayed /
        // handle-mismatched tokens. Consuming up-front means a replay never
        // reaches `create_fifo` and cannot spawn a second blocking writer.
        ctx.consume_use_token(&self.use_token, &self.handle).await?;

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
        // Zeroizing so the plaintext is wiped once the writer task drops it (or
        // on any early return before the task is spawned).
        let plaintext = Zeroizing::new(ctx.crypto.aead_decrypt(
            &self.dek_bytes,
            &blob.nonce,
            &cipher_with_tag,
            &blob.associated_data,
        )?);

        // Generate opaque token and build FIFO path.
        let token_bytes = ctx.crypto.random_bytes_32();
        let opaque_token = hex::encode(token_bytes);
        let fifo_path = build_fifo_path(&opaque_token);

        // Create the named pipe (UNIX only).
        create_fifo(&fifo_path)?;

        // Audit BEFORE spawning the writer task.
        //
        // BUG-07: the writer is a `spawn_blocking` thread that blocks on
        // `open(FIFO, O_WRONLY)` until a reader connects — it cannot be aborted
        // once running. If the audit write failed *after* the spawn, that thread
        // would block forever and the FIFO would leak. We therefore persist the
        // audit entry first (BUG-06: atomic persist-then-advance) and spawn the
        // writer only once the operation is durably recorded; every error path
        // before the spawn removes the FIFO and leaves no blocked thread.
        let hmac_key = match ctx.require_hmac_key().await {
            Ok(key) => key,
            Err(e) => {
                let _ = tokio::fs::remove_file(&fifo_path).await;
                return Err(e);
            }
        };
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::WriteTempfile,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .handle(self.handle.clone())
        .sensitivity(secret.sensitivity)
        .caller_program("merkle-agent");
        if let Err(e) = crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await {
            let _ = tokio::fs::remove_file(&fifo_path).await;
            return Err(e);
        }

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
                    let _ = f.write_all(plaintext.as_slice());
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::commands::unseal_vault::test_support;
    use crate::commands::use_token::UseTokenCommand;

    use merkle_types::UuidV7;

    /// Issue a valid use-token for `handle` via the production command path.
    async fn issue_token(ctx: &AppContext, namespace_id: NamespaceId, handle: Handle) -> String {
        UseTokenCommand {
            namespace_id,
            handle,
            session_id: UuidV7::new(),
        }
        .execute(ctx)
        .await
        .expect("issue use-token")
        .use_token
    }

    /// BUG-07: when the audit write fails the FIFO must be removed and no
    /// blocked writer thread may be left behind. Auditing happens *before* the
    /// writer task is spawned, so a failed audit never spawns the blocking
    /// thread and the FIFO is cleaned up.
    #[tokio::test]
    async fn fifo_removed_when_audit_write_fails() {
        // Unique per-test token so the materialized FIFO path never collides with
        // a sibling test running concurrently.
        const TOKEN: [u8; 32] = [0x23; 32];
        let (ctx, storage) = test_support::make_failing_ctx_with_token(TOKEN).await;
        test_support::unseal_ctx(&ctx).await;
        let (namespace_id, handle) = test_support::seed_secret(&ctx).await;

        // A valid token must be issued before arming the audit failure: it is
        // now consumed up-front, before the FIFO is created.
        let use_token = issue_token(&ctx, namespace_id, handle.clone()).await;

        let token = hex::encode(TOKEN);
        let path = build_fifo_path(&token);
        let _ = std::fs::remove_file(&path);

        storage.arm_audit_failure();
        let result = WriteFifoCommand {
            namespace_id,
            handle,
            dek_bytes: test_support::TEST_DEK,
            use_token,
        }
        .execute(&ctx)
        .await;

        assert!(result.is_err(), "audit failure must surface as an error");
        assert!(
            !path.exists(),
            "BUG-07: FIFO must be removed when the audit write fails"
        );
    }

    /// BUG-01: an unknown token is rejected before any FIFO is created, so no
    /// blocking writer thread is ever spawned.
    #[tokio::test]
    async fn unknown_token_creates_no_fifo() {
        // Unique per-test token so this defensive path cleanup cannot disturb a
        // sibling test's FIFO under concurrent execution.
        const TOKEN: [u8; 32] = [0x24; 32];
        let (ctx, _storage) = test_support::make_failing_ctx_with_token(TOKEN).await;
        test_support::unseal_ctx(&ctx).await;
        let (namespace_id, handle) = test_support::seed_secret(&ctx).await;

        let path = build_fifo_path(&hex::encode(TOKEN));
        let _ = std::fs::remove_file(&path);

        let result = WriteFifoCommand {
            namespace_id,
            handle,
            dek_bytes: test_support::TEST_DEK,
            use_token: "never-issued-token".to_owned(),
        }
        .execute(&ctx)
        .await;

        assert!(
            matches!(result, Err(AppError::InvalidInput(_))),
            "BUG-01: an unknown token must be rejected, got: {result:?}"
        );
        assert!(
            !path.exists(),
            "BUG-01: a rejected token must not create a FIFO"
        );
    }
}
