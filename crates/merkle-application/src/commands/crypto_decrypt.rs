//! `CryptoDecryptCommand` — AEAD decrypt with a vault-stored key.
//!
//! Loads the secret at `key_handle`, decrypts it to obtain the 32-byte
//! symmetric key, then uses that key to AEAD-decrypt the supplied `ciphertext`.
//! The 24-byte nonce must be prepended to the ciphertext (first 24 bytes).
//! Audited with `op=crypto_decrypt`.

use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for crypto-decrypt.
#[derive(Debug)]
pub struct CryptoDecryptCommand {
    /// Namespace owning the decryption key secret.
    pub namespace_id: NamespaceId,
    /// Handle to the secret holding the 32-byte AEAD key.
    pub key_handle: Handle,
    /// 32-byte namespace DEK for decrypting the key secret.
    pub dek_bytes: [u8; 32],
    /// Ciphertext bytes to decrypt. Format: `[nonce 24 bytes || ciphertext || tag 16 bytes]`.
    pub ciphertext: Vec<u8>,
    /// Additional associated data bound to the ciphertext tag.
    pub aad: Vec<u8>,
}

/// Output of `CryptoDecryptCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CryptoDecryptOutput {
    /// Decrypted plaintext bytes.
    ///
    /// The calling adapter MUST zeroize this buffer after use.
    pub plaintext: Vec<u8>,
}

impl CryptoDecryptCommand {
    /// Execute crypto-decrypt.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::NotFound`] — key secret not found.
    /// - [`AppError::Crypto`] — AEAD decryption failed (key or ciphertext).
    /// - [`AppError::InvalidInput`] — ciphertext is too short to contain a nonce.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<CryptoDecryptOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(key_handle = %self.key_handle, "crypto_decrypt: loading decryption key");

        // Require at least nonce (24 bytes) + tag (16 bytes) = 40 bytes.
        if self.ciphertext.len() < 40 {
            return Err(AppError::InvalidInput(
                "crypto_decrypt: ciphertext too short (expected nonce || ciphertext || tag)".into(),
            ));
        }

        // Load and decrypt the decryption key secret.
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

        let aead_key: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            AppError::InvalidInput(format!(
                "crypto_decrypt: expected 32-byte AEAD key, got {} bytes",
                key_bytes.len()
            ))
        })?;

        // Extract nonce from the first 24 bytes of ciphertext.
        let nonce: [u8; 24] = self.ciphertext[..24].try_into().map_err(|_| {
            AppError::InvalidInput("crypto_decrypt: nonce extraction failed".into())
        })?;
        let body = &self.ciphertext[24..];

        let plaintext = ctx.crypto.aead_decrypt(&aead_key, &nonce, body, &self.aad)?;

        // Audit: op=crypto_decrypt.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::CryptoDecrypt,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .handle(self.key_handle.clone())
        .sensitivity(secret.sensitivity)
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        drop(log);
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!(key_handle = %self.key_handle, "crypto_decrypt: decryption complete");
        Ok(CryptoDecryptOutput { plaintext })
    }
}
