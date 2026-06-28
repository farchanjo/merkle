//! `CryptoSignCommand` — Ed25519 sign with a vault-stored private key.
//!
//! Loads the secret at `key_handle`, decrypts the private key bytes, and
//! signs `message` via [`Crypto::ed25519_sign`]. The 64-byte signature is
//! returned in hex encoding. Audited with `op=crypto_sign`.

use merkle_ports::Ed25519PrivateKey;
use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for crypto-sign.
#[derive(Debug)]
pub struct CryptoSignCommand {
    /// Namespace owning the signing key secret.
    pub namespace_id: NamespaceId,
    /// Handle to the secret holding the Ed25519 32-byte private key seed.
    pub key_handle: Handle,
    /// 32-byte namespace DEK for decrypting the key secret.
    pub dek_bytes: [u8; 32],
    /// Message bytes to sign.
    pub message: Vec<u8>,
}

/// Output of `CryptoSignCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CryptoSignOutput {
    /// Hex-encoded 64-byte Ed25519 signature.
    pub signature_hex: String,
}

impl CryptoSignCommand {
    /// Execute crypto-sign.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::NotFound`] — key secret not found.
    /// - [`AppError::Crypto`] — AEAD decryption failed.
    /// - [`AppError::InvalidInput`] — key bytes are not 32 bytes long.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<CryptoSignOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(key_handle = %self.key_handle, "crypto_sign: loading signing key");

        // Load and decrypt the private key secret.
        let secret = ctx
            .storage
            .get_secret_by_handle(&self.key_handle)
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
        let key_bytes = ctx.crypto.aead_decrypt(
            &self.dek_bytes,
            &blob.nonce,
            &cipher_with_tag,
            &blob.associated_data,
        )?;

        // The decrypted payload must be exactly 32 bytes (Ed25519 seed).
        let seed: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            AppError::InvalidInput(format!(
                "crypto_sign: expected 32-byte Ed25519 seed, got {} bytes",
                key_bytes.len()
            ))
        })?;

        let sk = Ed25519PrivateKey(seed);
        let signature: [u8; 64] = ctx.crypto.ed25519_sign(&sk, &self.message);
        let signature_hex = hex::encode(signature);

        // Audit: op=crypto_sign.
        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::CryptoSign,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .handle(self.key_handle.clone())
        .sensitivity(secret.sensitivity)
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(key_handle = %self.key_handle, "crypto_sign: signature produced");
        Ok(CryptoSignOutput { signature_hex })
    }
}
