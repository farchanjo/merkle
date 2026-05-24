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
        std::fs::set_permissions(&tmp_path, perms)
            .map_err(|e| AppError::Domain(format!("write_tempfile: chmod failed: {e}")))?;

        let expires_at = Rfc3339Timestamp::now();

        // Domain entity (path stored server-side only — never crosses MCP boundary).
        let _tempfile = Tempfile {
            opaque_token: opaque_token.clone(),
            real_path_redacted: tmp_path,
            mode: 0o600,
            expires_at,
        };

        // Audit: op=write_tempfile.
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
