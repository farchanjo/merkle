//! `DisasterRecoverCommand` — recover from Master Key loss via Recovery Key.
//!
//! Operator supplies the out-of-band age identity (Recovery Key) and a v2
//! dual-recipient Backup. The command:
//! 1. Verifies the Recovery Key matches the vault's recovery recipient.
//! 2. Decrypts the Backup (HMAC is not re-checked without the audit HMAC key).
//! 3. Decrypts the embedded recovery-wrapped Vault Root Key.
//! 4. Generates a fresh Master Key, dual-wraps the recovered VRK, stores keychain.
//! 5. Rehydrates secrets and unseals the vault with the recovered VRK.
//! 6. Audits `op=disaster_recovery`.

use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use merkle_domain_identity::{KEYCHAIN_ACCOUNT_MASTER_KEY, KEYCHAIN_SERVICE, VaultRootKey};
use merkle_ports::{AgeIdentity, AgeRecipient};
use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::backup_payload::BackupPlaintext;
use crate::commands::init_vault::{
    KEYCHAIN_ACCOUNT_VRK_MASTER, KEYCHAIN_ACCOUNT_VRK_RECOVERY, VRK_MASTER_AAD,
};
use crate::commands::unseal_vault::{audit_commit, derive_audit_hmac_key};
use crate::{AppContext, AppError};

/// Input for disaster recovery.
pub struct DisasterRecoverCommand {
    /// Operator-held recovery age identity (`AGE-SECRET-KEY-1…`).
    pub recovery_identity: AgeIdentity,
    /// Path to a dual-recipient `.merkle.age` backup (v2 with VRK wrap).
    pub backup_path: PathBuf,
}

impl std::fmt::Debug for DisasterRecoverCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisasterRecoverCommand")
            .field("recovery_identity", &"[REDACTED]")
            .field("backup_path", &self.backup_path)
            .finish()
    }
}

/// Output of a successful disaster recovery.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DisasterRecoverOutput {
    /// Number of secrets rehydrated from the Backup.
    pub secrets_restored: u32,
    /// Confirmation the vault is Unsealed after re-wrap.
    pub unsealed: bool,
}

impl DisasterRecoverCommand {
    /// Execute disaster recovery.
    ///
    /// # Errors
    ///
    /// - [`AppError::InvalidInput`] — recovery key mismatch / empty path.
    /// - [`AppError::Crypto`] — decrypt failed.
    /// - [`AppError::Domain`] — backup is not v2 or VRK unwrap failed.
    /// - [`AppError::Keychain`] / [`AppError::Storage`] — persistence failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<DisasterRecoverOutput, AppError> {
        if self.recovery_identity.0.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "recovery_identity must not be empty".into(),
            ));
        }
        if self.backup_path.as_os_str().is_empty() {
            return Err(AppError::InvalidInput("backup_path must not be empty".into()));
        }

        info!(path = %self.backup_path.display(), "disaster_recover: starting");

        // 1. Fingerprint check against stored recovery recipient.
        let stored_pubkey = {
            let id = ctx.identity.read().await;
            id.recovery_pubkey().identity_pubkey().to_owned()
        };
        if !recovery_identity_matches(ctx, &self.recovery_identity, &stored_pubkey)? {
            // Deny audit best-effort (vault may be sealed; still try with empty ns).
            if let Ok(hmac) = ctx.require_hmac_key().await {
                let params = merkle_domain_audit_compliance::AppendParams::new(
                    AuditOp::DisasterRecovery,
                    AuditOutcome::Deny,
                    NamespaceId::default(),
                )
                .caller_program("merkle-agent")
                .denial_reason("recovery_key_fingerprint_mismatch");
                let _ = audit_commit(ctx, params, &hmac).await;
            }
            return Err(AppError::InvalidInput(
                "recovery_key_fingerprint_mismatch".into(),
            ));
        }

        // 2. Decrypt backup with recovery identity.
        let ciphertext = tokio::fs::read(&self.backup_path)
            .await
            .map_err(|e| AppError::Domain(format!("failed to read backup: {e}")))?;
        let plaintext = ctx
            .crypto
            .age_decrypt(&self.recovery_identity, &ciphertext)?;
        let payload = BackupPlaintext::decode(&plaintext).map_err(AppError::Domain)?;
        let Some(vrk_age) = payload.vrk_recovery_age() else {
            return Err(AppError::Domain(
                "backup is not v2 (missing recovery-wrapped VRK); cannot disaster-recover".into(),
            ));
        };

        // 3. Unwrap VRK with recovery identity.
        let vrk_vec = ctx
            .crypto
            .age_decrypt(&self.recovery_identity, vrk_age)?;
        let vrk_bytes = Zeroizing::new(
            <[u8; 32]>::try_from(vrk_vec.as_slice())
                .map_err(|_| AppError::Domain("recovered VRK has wrong length".into()))?,
        );

        // 4. Fresh Master Key + dual re-wrap + keychain store.
        let master_key_bytes = Zeroizing::new(ctx.crypto.random_bytes_32());
        ctx.keychain
            .store(
                KEYCHAIN_SERVICE,
                KEYCHAIN_ACCOUNT_MASTER_KEY,
                master_key_bytes.as_slice(),
            )
            .await
            .map_err(AppError::Keychain)?;

        let nonce_master: [u8; 24] = ctx.crypto.random_bytes_24();
        let wrapped_by_master = ctx.crypto.aead_encrypt(
            &master_key_bytes,
            &nonce_master,
            vrk_bytes.as_slice(),
            VRK_MASTER_AAD,
        )?;
        let master_wrapped_payload = {
            let mut buf = Vec::with_capacity(24 + wrapped_by_master.len());
            buf.extend_from_slice(&nonce_master);
            buf.extend_from_slice(&wrapped_by_master);
            BASE64.encode(&buf).into_bytes()
        };
        if let Err(e) = ctx
            .keychain
            .store(
                KEYCHAIN_SERVICE,
                KEYCHAIN_ACCOUNT_VRK_MASTER,
                &master_wrapped_payload,
            )
            .await
        {
            let _ = ctx
                .keychain
                .delete(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_MASTER_KEY)
                .await;
            return Err(AppError::Keychain(e));
        }

        let wrapped_by_recovery = ctx.crypto.age_encrypt(
            &[AgeRecipient(stored_pubkey.clone())],
            vrk_bytes.as_slice(),
        )?;
        let recovery_wrapped_payload = BASE64.encode(&wrapped_by_recovery).into_bytes();
        if let Err(e) = ctx
            .keychain
            .store(
                KEYCHAIN_SERVICE,
                KEYCHAIN_ACCOUNT_VRK_RECOVERY,
                &recovery_wrapped_payload,
            )
            .await
        {
            warn!("disaster_recover: failed to persist recovery wrap; rolling back master");
            let _ = ctx
                .keychain
                .delete(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_MASTER_KEY)
                .await;
            let _ = ctx
                .keychain
                .delete(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_VRK_MASTER)
                .await;
            return Err(AppError::Keychain(e));
        }

        // 5. Rehydrate secrets.
        let mut secrets_restored = 0_u32;
        for secret in payload.secrets() {
            ctx.storage.put_secret(secret).await?;
            secrets_restored = secrets_restored.saturating_add(1);
        }

        // 6. Unseal in-memory with recovered VRK + derived audit HMAC key.
        let hmac_key = derive_audit_hmac_key(ctx.crypto.as_ref(), &vrk_bytes);
        {
            let mut hmac_guard = ctx.hmac_key.write().await;
            *hmac_guard = Some(hmac_key);
        }
        {
            let mut identity = ctx.identity.write().await;
            // If already unsealed, seal first so begin_unseal is legal.
            if identity.is_unsealed() {
                identity
                    .seal()
                    .map_err(|e| AppError::Domain(e.to_string()))?;
            }
            let preconditions = merkle_domain_identity::UnsealPreconditions {
                security_profile: merkle_types::SecurityProfile::Balanced,
                mlock_succeeded: true,
                entropy_seeded: true,
                keychain_reachable: true,
            };
            identity
                .begin_unseal(preconditions)
                .map_err(|e| AppError::Domain(e.to_string()))?;
            identity
                .complete_unseal(VaultRootKey::from_bytes(*vrk_bytes))
                .map_err(|e| AppError::Domain(e.to_string()))?;
        }

        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::DisasterRecovery,
            AuditOutcome::Allow,
            NamespaceId::default(),
        )
        .caller_program("merkle-agent");
        audit_commit(ctx, params, &hmac_key).await?;
        ctx.touch_activity().await;

        info!(
            secrets_restored,
            "disaster_recover: complete — vault unsealed with re-wrapped master key"
        );
        Ok(DisasterRecoverOutput {
            secrets_restored,
            unsealed: true,
        })
    }
}

fn recovery_identity_matches(
    ctx: &AppContext,
    identity: &AgeIdentity,
    stored_pubkey: &str,
) -> Result<bool, AppError> {
    let recipient = AgeRecipient(stored_pubkey.to_owned());
    let sentinel = b"merkle-disaster-recovery-verify";
    let ciphertext = ctx.crypto.age_encrypt(&[recipient], sentinel)?;
    Ok(ctx.crypto.age_decrypt(identity, &ciphertext).is_ok())
}
