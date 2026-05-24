//! `RevokeTempfileCommand` — delete a tempfile or FIFO by opaque token.
//!
//! Resolves the opaque token to the actual filesystem path (by reconstructing
//! it from the same naming convention used at creation), then removes the
//! file. The MCP transport supplies only the opaque token, never the real
//! path. Audited with `op=write_tempfile` (closest available op in the closed
//! enum for tempfile lifecycle operations; no dedicated revoke op exists).

use std::path::PathBuf;

use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for revoking a tempfile.
#[derive(Debug)]
pub struct RevokeTempfileCommand {
    /// Opaque token previously returned by `write_tempfile` or `write_fifo`.
    pub opaque_token: String,
    /// Namespace to use for the audit entry.
    pub namespace_id: NamespaceId,
}

/// Output of `RevokeTempfileCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RevokeTempfileOutput {
    /// `true` when the file was found and deleted.
    pub revoked: bool,
}

impl RevokeTempfileCommand {
    /// Execute revoke-tempfile.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::InvalidInput`] — empty opaque token.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<RevokeTempfileOutput, AppError> {
        ctx.require_unsealed().await?;

        if self.opaque_token.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "opaque_token must not be empty".into(),
            ));
        }

        info!(opaque_token = %self.opaque_token, "revoke_tempfile: revoking");

        // Reconstruct the two candidate paths (tempfile and FIFO).
        let tmp_path = resolve_tmp_path(&self.opaque_token);
        let fifo_path = resolve_fifo_path(&self.opaque_token);

        // Attempt to remove whichever path exists. Both removals are
        // best-effort — a missing file is not an error (already cleaned up).
        let tmp_removed = tokio::fs::remove_file(&tmp_path).await.is_ok();
        let fifo_removed = tokio::fs::remove_file(&fifo_path).await.is_ok();
        let revoked = tmp_removed || fifo_removed;

        // Audit (no matter whether the file existed or not — the intent was to revoke).
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::WriteTempfile,
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

        info!(revoked = revoked, "revoke_tempfile: complete");
        Ok(RevokeTempfileOutput { revoked })
    }
}

/// Resolve the tempfile path from an opaque token.
fn resolve_tmp_path(opaque_token: &str) -> PathBuf {
    std::env::temp_dir().join(format!("merkle_{opaque_token}.tmp"))
}

/// Resolve the FIFO path from an opaque token.
fn resolve_fifo_path(opaque_token: &str) -> PathBuf {
    std::env::temp_dir().join(format!("merkle_{opaque_token}.fifo"))
}
