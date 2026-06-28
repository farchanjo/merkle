//! `WriteTempfileCommand` — materialize a secret to a 0600 tempfile.
//!
//! Resolves the secret by handle, decrypts the private blob, writes the
//! plaintext to a temporary file with mode 0600, and returns an opaque token
//! (not the real path). Audited with `op=write_tempfile`.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use merkle_domain_access_mediation::tempfile::Tempfile;
use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId, Rfc3339Timestamp};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for writing a tempfile.
#[derive(Debug)]
pub struct WriteTempfileCommand {
    /// Namespace owning the secret.
    pub namespace_id: NamespaceId,
    /// Secret handle to materialize.
    pub handle: Handle,
    /// 32-byte namespace DEK for decryption.
    pub dek_bytes: [u8; 32],
    /// Opaque single-use authorization token issued by `UseTokenCommand`.
    ///
    /// Validated and consumed before any plaintext is materialized; a missing,
    /// expired, replayed, or handle-mismatched token rejects the request.
    pub use_token: String,
}

/// Output of `WriteTempfileCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WriteTempfileOutput {
    /// Opaque token — the only identifier returned to the MCP transport.
    ///
    /// The real filesystem path is NEVER included.
    pub opaque_token: String,
    /// RFC 3339 session-lifetime expiration timestamp.
    pub expires_at: Rfc3339Timestamp,
}

impl WriteTempfileCommand {
    /// Execute write-tempfile.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::NotFound`] — secret not found for handle.
    /// - [`AppError::Crypto`] — AEAD decryption failed.
    /// - [`AppError::Domain`] — tempfile I/O or chmod failed.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<WriteTempfileOutput, AppError> {
        ctx.require_unsealed().await?;

        // Enforce the single-use + 60s-TTL use-token BEFORE any plaintext is
        // produced: reject unknown / expired / replayed / handle-mismatched
        // tokens. Consumption is atomic, so a replay can never materialize a
        // second tempfile.
        ctx.consume_use_token(&self.use_token, &self.handle).await?;

        info!(handle = %self.handle, "write_tempfile: resolving secret");

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

        // Generate an opaque token for the tempfile registry key.
        let token_bytes = ctx.crypto.random_bytes_32();
        let opaque_token = hex::encode(token_bytes);

        // Write to a temporary file with mode 0600.
        let tmp_path = build_tmp_path(&opaque_token);
        tokio::fs::write(&tmp_path, &plaintext)
            .await
            .map_err(|e| AppError::Domain(format!("write_tempfile: I/O error: {e}")))?;

        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(&tmp_path, perms) {
            // BUG-09: never leave a plaintext tempfile behind on an early return.
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(AppError::Domain(format!(
                "write_tempfile: chmod failed: {e}"
            )));
        }

        let expires_at = Rfc3339Timestamp::now();

        // Domain entity (path stored server-side only — never crosses MCP boundary).
        let _tempfile = Tempfile {
            opaque_token: opaque_token.clone(),
            real_path_redacted: tmp_path.clone(),
            mode: 0o600,
            expires_at,
        };

        // Audit: op=write_tempfile (BUG-06: persist-then-advance atomically).
        // BUG-09: the plaintext tempfile must not survive a failed audit write,
        // so every fallible step from here removes it before returning the error.
        let hmac_key = match ctx.require_hmac_key().await {
            Ok(key) => key,
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
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
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e);
        }

        info!(handle = %self.handle, "write_tempfile: tempfile written");
        Ok(WriteTempfileOutput {
            opaque_token,
            expires_at,
        })
    }
}

/// Build the temporary file path from the opaque token.
fn build_tmp_path(opaque_token: &str) -> PathBuf {
    std::env::temp_dir().join(format!("merkle_{opaque_token}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::unseal_vault::test_support;
    use crate::commands::use_token::UseTokenCommand;

    use chrono::{Duration, Utc};
    use merkle_domain_access_mediation::use_token::UseToken;
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

    fn make_cmd(
        namespace_id: NamespaceId,
        handle: Handle,
        use_token: String,
    ) -> WriteTempfileCommand {
        WriteTempfileCommand {
            namespace_id,
            handle,
            dek_bytes: test_support::TEST_DEK,
            use_token,
        }
    }

    /// BUG-09: a plaintext tempfile must not survive a failed audit write.
    #[tokio::test]
    async fn tempfile_removed_when_audit_write_fails() {
        // Unique per-test token so the materialized tmp path never collides with
        // a sibling test running concurrently.
        const TOKEN: [u8; 32] = [0x21; 32];
        let (ctx, storage) = test_support::make_failing_ctx_with_token(TOKEN).await;
        test_support::unseal_ctx(&ctx).await;
        let (namespace_id, handle) = test_support::seed_secret(&ctx).await;

        // A valid token must be issued before arming the audit failure, since
        // the token is now consumed up-front, before any plaintext is written.
        let use_token = issue_token(&ctx, namespace_id, handle.clone()).await;

        // FixedTokenCrypto yields a deterministic token, so the path is known.
        let token = hex::encode(TOKEN);
        let path = build_tmp_path(&token);
        let _ = std::fs::remove_file(&path);

        storage.arm_audit_failure();
        let result = make_cmd(namespace_id, handle, use_token)
            .execute(&ctx)
            .await;

        assert!(result.is_err(), "audit failure must surface as an error");
        assert!(
            !path.exists(),
            "BUG-09: tempfile must be removed when the audit write fails"
        );
    }

    /// BUG-01: a valid use-token authorizes exactly one materialization; a
    /// second attempt with the same token is rejected as a replay.
    #[tokio::test]
    async fn valid_token_is_consumed_exactly_once() {
        // Unique per-test token so the materialized tmp path never collides with
        // a sibling test running concurrently.
        const TOKEN: [u8; 32] = [0x22; 32];
        let (ctx, _storage) = test_support::make_failing_ctx_with_token(TOKEN).await;
        test_support::unseal_ctx(&ctx).await;
        let (namespace_id, handle) = test_support::seed_secret(&ctx).await;

        let use_token = issue_token(&ctx, namespace_id, handle.clone()).await;
        let path = build_tmp_path(&hex::encode(TOKEN));
        let _ = std::fs::remove_file(&path);

        let first = make_cmd(namespace_id, handle.clone(), use_token.clone())
            .execute(&ctx)
            .await;
        assert!(first.is_ok(), "first use of a valid token must succeed");

        let replay = make_cmd(namespace_id, handle, use_token)
            .execute(&ctx)
            .await;
        match replay {
            Err(AppError::Domain(msg)) => assert!(
                msg.contains("already consumed"),
                "BUG-01: replay must be rejected as already-consumed, got: {msg}"
            ),
            other => panic!("BUG-01: replay must be rejected, got: {other:?}"),
        }

        let _ = std::fs::remove_file(&path);
    }

    /// BUG-01: an unknown (never-issued) token is rejected.
    #[tokio::test]
    async fn unknown_token_is_rejected() {
        let (ctx, _storage) = test_support::make_failing_ctx().await;
        test_support::unseal_ctx(&ctx).await;
        let (namespace_id, handle) = test_support::seed_secret(&ctx).await;

        let result = make_cmd(namespace_id, handle, "never-issued-token".to_owned())
            .execute(&ctx)
            .await;
        assert!(
            matches!(result, Err(AppError::InvalidInput(_))),
            "BUG-01: an unknown token must be rejected, got: {result:?}"
        );
    }

    /// BUG-01: an expired token is rejected even though it was once registered.
    #[tokio::test]
    async fn expired_token_is_rejected() {
        let (ctx, _storage) = test_support::make_failing_ctx().await;
        test_support::unseal_ctx(&ctx).await;
        let (namespace_id, handle) = test_support::seed_secret(&ctx).await;

        let secret = ctx
            .storage
            .get_secret_by_handle(&handle)
            .await
            .expect("storage")
            .expect("secret present");
        let past: Rfc3339Timestamp = (Utc::now() - Duration::seconds(120))
            .to_rfc3339()
            .parse()
            .expect("past timestamp");
        let expired = UseToken::new(
            [0x22; 32],
            secret.id,
            UuidV7::new(),
            handle.clone(),
            Rfc3339Timestamp::now(),
            past,
        );
        let token_str = expired.to_string();
        ctx.register_use_token(expired).await;

        let result = make_cmd(namespace_id, handle, token_str)
            .execute(&ctx)
            .await;
        match result {
            Err(AppError::Domain(msg)) => assert!(
                msg.contains("expired"),
                "BUG-01: expired token must be rejected, got: {msg}"
            ),
            other => panic!("BUG-01: expired token must be rejected, got: {other:?}"),
        }
    }
}
