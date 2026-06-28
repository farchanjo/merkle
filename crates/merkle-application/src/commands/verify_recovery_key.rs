//! `VerifyRecoveryKeyCommand` — verify a recovery key against the stored public key.
//!
//! Derives the age public key from the supplied age identity by encrypting a
//! test sentinel to the stored pubkey and attempting decryption. No plaintext
//! secret material is stored or logged. Audited with `op=doctor`.

use merkle_ports::{AgeIdentity, AgeRecipient};
use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for verifying a recovery key.
#[derive(Debug)]
pub struct VerifyRecoveryKeyCommand {
    /// Age identity string (starts with `AGE-SECRET-KEY-1`) to test.
    pub age_identity: String,
    /// Namespace to use for the audit entry.
    pub namespace_id: NamespaceId,
}

/// Output of `VerifyRecoveryKeyCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct VerifyRecoveryKeyOutput {
    /// `true` when the supplied identity matches the stored recovery public key.
    pub matches: bool,
}

impl VerifyRecoveryKeyCommand {
    /// Execute verify-recovery-key.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::InvalidInput`] — empty identity string.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<VerifyRecoveryKeyOutput, AppError> {
        ctx.require_unsealed().await?;

        if self.age_identity.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "age_identity must not be empty".into(),
            ));
        }

        info!("verify_recovery_key: verifying recovery key against stored pubkey");

        // Read the stored age recipient (public key) from vault identity.
        let stored_pubkey_str = {
            let id_guard = ctx.identity.read().await;
            id_guard.recovery_pubkey().identity_pubkey().to_owned()
        };

        // Encrypt a test sentinel to the stored public key, then attempt to
        // decrypt with the supplied identity. If decryption succeeds they match.
        let recipient = AgeRecipient(stored_pubkey_str);
        let sentinel = b"merkle-recovery-key-verify-sentinel";
        let ciphertext = ctx.crypto.age_encrypt(&[recipient], sentinel)?;

        let identity = AgeIdentity(self.age_identity.clone());
        let matches = ctx.crypto.age_decrypt(&identity, &ciphertext).is_ok();

        // Audit: op=doctor — no plaintext stored in any audit field.
        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Doctor,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(matches = matches, "verify_recovery_key: complete");
        Ok(VerifyRecoveryKeyOutput { matches })
    }
}
