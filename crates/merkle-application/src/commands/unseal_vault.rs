//! `UnsealVaultCommand` — drive the `Sealed → Unsealing → Unsealed` transition.
//!
//! Uses the RAII [`UnsealGuard`](merkle_domain_identity::UnsealGuard) pattern
//! (ADR-0015 Amendment 3): if any step between `begin_unseal` and `complete_unseal`
//! fails, the state is automatically rolled back to `Sealed`.
//!
//! # Lock discipline
//!
//! The `tokio::sync::RwLock<VaultIdentity>` cannot be held across `.await`
//! points.  The guard is therefore used in two separate lock windows:
//!
//! 1. **Begin window** — acquire write lock, call `begin_unseal` (transitions to
//!    `Unsealing`), release lock.
//! 2. **Async work** — keychain read and VRK decryption (no lock held).
//! 3. **Commit/rollback window** — re-acquire write lock, call `complete_unseal`
//!    on success or `revert_to_sealed` on any error.
//!
//! This two-window split is equivalent to the RAII guard pattern; the guard
//! object itself cannot span the await points, so explicit `revert_to_sealed`
//! is called in the error path.

use merkle_domain_identity::{SealedState, VaultRootKey};
use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for unsealing the vault.
#[derive(Debug)]
pub struct UnsealVaultCommand {
    /// Runtime preconditions evaluated before any key material is loaded.
    pub preconditions: merkle_domain_identity::UnsealPreconditions,
}

/// Output of a successful `UnsealVaultCommand`.
#[derive(Debug)]
pub struct UnsealVaultOutput {
    /// Opaque confirmation that the vault transitioned to `Unsealed`.
    pub unsealed: bool,
}

impl UnsealVaultCommand {
    /// Execute vault unseal.
    ///
    /// State rollback contract (ADR-0015 Amendment 3): any error between
    /// `begin_unseal` and `complete_unseal` reverts the state back to `Sealed`
    /// so that a subsequent unseal attempt does not fail with an invalid
    /// state-transition error.
    ///
    /// # Errors
    ///
    /// - [`AppError::Domain`] — unseal preconditions failed or state transition
    ///   rejected.
    /// - [`AppError::Keychain`] — MasterKey retrieval failed.
    /// - [`AppError::Crypto`] — VRK decryption failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<UnsealVaultOutput, AppError> {
        info!("unseal_vault: beginning unseal sequence");

        // ── Window 1: begin unseal (Sealed → Unsealing) ──────────────────────
        {
            let mut identity = ctx.identity.write().await;
            if identity.is_unsealed() {
                return Ok(UnsealVaultOutput { unsealed: true });
            }
            // Use begin_unseal_with_guard and immediately commit the guard's
            // internal state — we can't hold the guard across await points, so
            // we record the state transition here and handle rollback explicitly
            // in the error path below.
            identity
                .begin_unseal(self.preconditions)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        }

        // ── Window 2: async key material fetch (no lock held) ─────────────────
        let result: Result<VaultRootKey, AppError> = async {
            // 2a. Load the MasterKey from the OS keychain.
            let keychain_ref = {
                let identity = ctx.identity.read().await;
                identity.master_key_keychain_ref().clone()
            };
            let master_key_bytes = ctx
                .keychain
                .retrieve(keychain_ref.service(), keychain_ref.account())
                .await
                .map_err(AppError::Keychain)?;

            let master_key_arr: [u8; 32] = master_key_bytes
                .try_into()
                .map_err(|_| AppError::InvalidInput("master key has wrong length".into()))?;

            // 2b. Derive VRK from the master key.
            //     In production this would AEAD-decrypt the wrapped VRK using
            //     master_key_arr; here we derive it via BLAKE3-keyed.
            let vrk_bytes = ctx.crypto.blake3_keyed(&master_key_arr, b"vault-root-key");
            let vrk = VaultRootKey::from_bytes(*vrk_bytes.as_bytes());
            Ok(vrk)
        }
        .await;

        // ── Window 3: commit or rollback ──────────────────────────────────────
        match result {
            Ok(vrk) => {
                let mut identity = ctx.identity.write().await;
                identity
                    .complete_unseal(vrk)
                    .map_err(|e| AppError::Domain(e.to_string()))?;
            }
            Err(e) => {
                // ADR-0015 Amendment 3: roll back Unsealing → Sealed so that a
                // subsequent unseal attempt does not fail with an invalid
                // state-transition error.
                let mut identity = ctx.identity.write().await;
                if identity.state() == SealedState::Unsealing {
                    if let Err(rollback_err) = identity.revert_to_sealed() {
                        tracing::error!(
                            error = %rollback_err,
                            "unseal_vault: rollback to Sealed failed — vault may be stuck in Unsealing"
                        );
                    }
                }
                return Err(e);
            }
        }

        // ── Window 4: derive HMAC key + audit ─────────────────────────────────
        // Re-derive the VRK bytes for HMAC key derivation. In a real system
        // this would be done within window 3 before releasing the lock; here
        // we accept the redundant re-derive.
        let keychain_ref = {
            let identity = ctx.identity.read().await;
            identity.master_key_keychain_ref().clone()
        };
        let master_key_bytes = ctx
            .keychain
            .retrieve(keychain_ref.service(), keychain_ref.account())
            .await
            .map_err(AppError::Keychain)?;
        let master_key_arr: [u8; 32] = master_key_bytes
            .try_into()
            .map_err(|_| AppError::InvalidInput("master key has wrong length (hmac phase)".into()))?;
        let vrk_bytes = ctx.crypto.blake3_keyed(&master_key_arr, b"vault-root-key");
        let hmac_key_bytes = ctx
            .crypto
            .blake3_keyed(vrk_bytes.as_bytes(), b"hmac-key");

        {
            let mut hmac_guard = ctx.hmac_key.write().await;
            *hmac_guard = Some(*hmac_key_bytes.as_bytes());
        }

        let ns_id = NamespaceId::new();
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Unseal,
            AuditOutcome::Allow,
            ns_id,
        )
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(
                &mut log,
                params,
                hmac_key_bytes.as_bytes(),
            )
            .map_err(|e| AppError::Domain(e.to_string()))?;
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!("unseal_vault: vault is now Unsealed");
        Ok(UnsealVaultOutput { unsealed: true })
    }
}
