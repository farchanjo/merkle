//! `SealVaultCommand` — drive the `Unsealed → ShuttingDown → Sealed` transition.

use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::{info, warn};
use zeroize::Zeroize as _;

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

        // Operator seal is only meaningful from a fully Unsealed vault. Reject
        // early when the vault is Sealed or mid-unseal (Unsealing): sealing must
        // never race into another client's in-flight unseal window. The domain
        // `seal()` re-checks this atomically under the identity write lock; this
        // is the fail-fast app-layer gate.
        ctx.require_unsealed().await?;

        // Attempt to append final audit entry while we still have the HMAC key.
        let hmac_key = ctx.hmac_key.read().await;
        if let Some(key) = *hmac_key {
            drop(hmac_key);
            let ns_id = NamespaceId::new();
            let params = merkle_domain_audit_compliance::AppendParams::new(
                AuditOp::Seal,
                AuditOutcome::Allow,
                ns_id,
            )
            .caller_program("merkle-agent");
            // BUG-06: `audit_commit` holds the audit-log write guard across
            // persistence and rolls the in-memory head back on failure, so a
            // concurrent command can never observe — or chain off — a
            // non-durable seal tail. Sealing must still proceed even when
            // persistence fails (the HMAC key is about to be dropped), but the
            // lost seal event is an audit-trail gap and MUST be surfaced.
            if let Err(e) = crate::commands::unseal_vault::audit_commit(ctx, params, &key).await {
                warn!(
                    error = %e,
                    "seal_vault: seal audit entry not persisted; in-memory head rolled back, sealing proceeds"
                );
            }
        } else {
            drop(hmac_key);
        }

        // Take and explicitly zero the key before dropping it. Assigning
        // `None` alone only drops a copyable array and leaves its bytes in the
        // allocation until reused.
        {
            let mut hmac_guard = ctx.hmac_key.write().await;
            if let Some(mut key) = hmac_guard.take() {
                key.zeroize();
            }
        }

        // Restore the in-memory audit log from the persisted PinnedHead so the
        // next unseal session continues the globally-monotonic seq counter (ADR-0009
        // line 209). Fall back to an empty log only when no pinned head exists yet
        // (pre-init or fresh DB) — that case is exercised by the init ceremony.
        {
            let pinned = ctx.storage.pinned_head().await?;
            let mut log = ctx.audit_log.write().await;
            *log = match pinned {
                Some(head) => merkle_domain_audit_compliance::AuditLog::restore_head(
                    head.head_hash,
                    head.head_seq,
                ),
                None => merkle_domain_audit_compliance::AuditLog::new(),
            };
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
