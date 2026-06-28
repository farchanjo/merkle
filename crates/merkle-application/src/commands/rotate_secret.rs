//! `RotateSecretCommand` — create a new `SecretVersion` for an existing secret.
//!
//! Decodes the payload according to [`ValueFormat`] before encrypting.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use merkle_domain_secret_storage::{
    PrivateBlob,
    secret_version::{SecretVersion, SecretVersionId},
};
use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId, Rfc3339Timestamp};
use tracing::info;

use crate::{AppContext, AppError, ValueFormat};

/// Input for rotating a secret.
#[derive(Debug)]
pub struct RotateSecretCommand {
    /// Namespace owning the secret.
    pub namespace_id: NamespaceId,

    /// Vault URI of the secret to rotate.
    pub handle: Handle,

    /// New payload bytes as received from the transport.
    ///
    /// Interpretation depends on [`value_format`].
    pub plaintext: Vec<u8>,

    /// How `plaintext` is encoded.
    pub value_format: ValueFormat,

    /// Namespace DEK version to use for this write.
    pub dek_version: u32,

    /// 32-byte plaintext namespace DEK.
    pub dek_bytes: [u8; 32],
}

/// Output of `RotateSecretCommand`.
#[derive(Debug)]
pub struct RotateSecretOutput {
    /// New version number assigned to the rotation.
    pub new_version_no: u32,
}

impl RotateSecretCommand {
    /// Execute rotate-secret.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::NotFound`] — no secret found for the handle.
    /// - [`AppError::Crypto`] — AEAD encryption failed.
    /// - [`AppError::Domain`] — rotation invariant violated.
    /// - [`AppError::Storage`] — persistence failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<RotateSecretOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(handle = %self.handle, "rotate_secret: loading current secret");

        // 1. Load existing secret.
        let mut secret = ctx
            .storage
            .get_secret_by_handle(&self.handle)
            .await?
            .ok_or(AppError::NotFound)?;

        // 2a. Decode payload.
        let decoded: Vec<u8> = match self.value_format {
            ValueFormat::Utf8 => self.plaintext.clone(),
            ValueFormat::Base64 => BASE64
                .decode(&self.plaintext)
                .map_err(|e| AppError::InvalidInput(format!("base64 decode failed: {e}")))?,
        };

        // 2b. Encrypt.
        let nonce = ctx.crypto.random_bytes_24();
        let aad = self.handle.to_string().into_bytes();
        let ciphertext = ctx
            .crypto
            .aead_encrypt(&self.dek_bytes, &nonce, &decoded, &aad)?;

        let tag_offset = ciphertext.len().saturating_sub(16);
        let aead_tag: [u8; 16] = ciphertext[tag_offset..]
            .try_into()
            .map_err(|_| AppError::Crypto(merkle_ports::CryptoError::AeadVerifyFailed))?;
        let cipher_body = ciphertext[..tag_offset].to_vec();

        let new_blob = PrivateBlob {
            ciphertext: cipher_body,
            nonce,
            aead_tag,
            associated_data: aad,
            dek_version: self.dek_version,
        };

        let current_version_no = secret
            .versions()
            .iter()
            .map(|v| v.version_no)
            .max()
            .unwrap_or(0);
        let new_version_no = current_version_no + 1;

        let new_version = SecretVersion {
            id: SecretVersionId::new(),
            secret_id: secret.id,
            version_no: new_version_no,
            blob: new_blob,
            dek_version: self.dek_version,
            created_at: Rfc3339Timestamp::now(),
            deprecated_at: None,
        };

        // 3. Rotate via the domain aggregate.
        let retention = merkle_domain_secret_storage::RetentionPolicy::new(3)
            .map_err(|e| AppError::Domain(e.to_string()))?;
        secret
            .rotate(new_version, &retention)
            .map_err(|e| AppError::Domain(e.to_string()))?;

        // 4. Persist.
        ctx.storage.put_secret(&secret).await?;

        // 5. Audit.
        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Rotate,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .handle(self.handle.clone())
        .sensitivity(secret.sensitivity)
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(handle = %self.handle, version = new_version_no, "rotate_secret: rotated");
        Ok(RotateSecretOutput { new_version_no })
    }
}
