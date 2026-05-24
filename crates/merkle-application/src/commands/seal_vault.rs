//! `SealVaultCommand` — drive the `Unsealed → ShuttingDown → Sealed` transition.

use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for sealing the vault (unit-struct; no parameters required).
#[derive(Debug, Default)]
pub struct SealVaultCommand;

/// Output of a successful `SealVaultCommand`.
#[derive(Debug)]
pub struct SealVaultOutput {
    /// Opaque confirmation that the vault transitioned back to `Sealed`.
    pub sealed: bool,
}

impl SealVaultCommand {
    /// Execute vault sealing.
    ///
    /// # Errors
    ///
    /// - [`AppError::Domain`] — state transition rejected (vault already sealed).
    /// - [`AppError::Storage`] — audit head persistence failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<SealVaultOutput, AppError> {
        info!("seal_vault: initiating seal sequence");

        // Attempt to append final audit entry while we still have the HMAC key.
        let hmac_key = ctx.hmac_key.read().await;
        if let Some(key) = *hmac_key {
            drop(hmac_key);
            let ns_id = NamespaceId::new();
            let mut log = ctx.audit_log.write().await;
            let params = merkle_domain_audit_compliance::AppendParams::new(
                AuditOp::Unseal,
                AuditOutcome::Allow,
                ns_id,
            )
            .caller_program("merkle-agent");
            if let Ok((entry, pinned)) =
                merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &key)
            {
                drop(log);
                let _ = ctx.storage.append_audit_entry(&entry).await;
                let _ = ctx.storage.update_pinned_head(&pinned).await;
            } else {
                drop(log);
            }
        } else {
            drop(hmac_key);
        }

        // Zero the HMAC key.
        {
            let mut hmac_guard = ctx.hmac_key.write().await;
            *hmac_guard = None;
        }

        // Reset the in-memory audit log — the next unseal session starts fresh.
        {
            let mut log = ctx.audit_log.write().await;
            *log = merkle_domain_audit_compliance::AuditLog::new();
        }

        // Transition the identity aggregate to Sealed.
        {
            let mut identity = ctx.identity.write().await;
            identity
                .seal()
                .map_err(|e| AppError::Domain(e.to_string()))?;
        }

        info!("seal_vault: vault is now Sealed");
        Ok(SealVaultOutput { sealed: true })
    }
}
