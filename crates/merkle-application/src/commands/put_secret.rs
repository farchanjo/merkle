//! `PutSecretCommand` — create or update a secret in storage.
//!
//! Validates that the vault is unsealed, decodes the payload according to
//! [`ValueFormat`], encrypts it via the Crypto port, constructs a `Secret`
//! aggregate and persists it via the Storage port, then appends an `AuditEntry`.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use merkle_domain_secret_storage::{
    PrivateBlob, PublicMetadata, Secret,
    secret_version::{SecretVersion, SecretVersionId},
};
use merkle_types::{
    AuditOp, AuditOutcome, CategoryName, Handle, NamespaceId, Rfc3339Timestamp, SecretId,
    Sensitivity, Tag,
};
use tracing::info;

use crate::{AppContext, AppError, ValueFormat};

/// Input for creating or updating a secret.
#[derive(Debug)]
pub struct PutSecretCommand {
    /// Target namespace identifier.
    pub namespace_id: NamespaceId,

    /// Opaque vault URI (`vault://<ns>/<cat>/<name>`).
    pub handle: Handle,

    /// Category for this secret (immutable after creation).
    pub category: CategoryName,

    /// Sensitivity classification.
    pub sensitivity: Sensitivity,

    /// Structured `key:value` tags.
    pub tags: Vec<Tag>,

    /// Whether the public metadata for this secret is exposed.
    pub expose_metadata: bool,

    /// Raw payload as received from the transport.
    ///
    /// Interpretation depends on [`value_format`]: when `Utf8` the bytes are
    /// used directly; when `Base64` they are decoded before encryption.
    pub plaintext: Vec<u8>,

    /// How `plaintext` is encoded.
    ///
    /// Defaults to [`ValueFormat::Utf8`].
    pub value_format: ValueFormat,

    /// Namespace DEK version to use for this write.
    pub dek_version: u32,

    /// 32-byte namespace DEK (plaintext) used to encrypt the payload.
    pub dek_bytes: [u8; 32],
}

/// Output of a successful `PutSecretCommand`.
#[derive(Debug)]
pub struct PutSecretOutput {
    /// The ID of the persisted secret.
    pub secret_id: SecretId,

    /// The vault URI for the persisted secret.
    pub handle: Handle,
}

impl PutSecretCommand {
    /// Execute put-secret.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault is not `Unsealed`.
    /// - [`AppError::Crypto`] — AEAD encryption failed.
    /// - [`AppError::Storage`] — persistence failed.
    /// - [`AppError::Domain`] — invariant violation in the `Secret` aggregate.
    pub async fn execute(&self, ctx: &AppContext) -> Result<PutSecretOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(handle = %self.handle, "put_secret: encrypting and persisting secret");

        // 1a. Decode payload according to value_format.
        let decoded: Vec<u8> = match self.value_format {
            ValueFormat::Utf8 => self.plaintext.clone(),
            ValueFormat::Base64 => BASE64
                .decode(&self.plaintext)
                .map_err(|e| AppError::InvalidInput(format!("base64 decode failed: {e}")))?,
        };

        // 1b. Encrypt the decoded payload.
        let nonce = ctx.crypto.random_bytes_24();
        let aad = self.handle.to_string().into_bytes();
        let ciphertext = ctx
            .crypto
            .aead_encrypt(&self.dek_bytes, &nonce, &decoded, &aad)?;

        // Split ciphertext from AEAD tag (last 16 bytes).
        let tag_offset = ciphertext.len().saturating_sub(16);
        let aead_tag: [u8; 16] = ciphertext[tag_offset..]
            .try_into()
            .map_err(|_| AppError::Crypto(merkle_ports::CryptoError::AeadVerifyFailed))?;
        let cipher_body = ciphertext[..tag_offset].to_vec();

        let blob = PrivateBlob {
            ciphertext: cipher_body,
            nonce,
            aead_tag,
            associated_data: aad,
            dek_version: self.dek_version,
        };

        // 2. Build the initial SecretVersion.
        let secret_id = SecretId::new();
        let version = SecretVersion {
            id: SecretVersionId::new(),
            secret_id,
            version_no: 1,
            blob,
            dek_version: self.dek_version,
            created_at: Rfc3339Timestamp::now(),
            deprecated_at: None,
        };

        // 3. Construct the Secret aggregate (validates invariants).
        let public_meta = PublicMetadata::new(self.expose_metadata);
        let secret = Secret::new(
            self.namespace_id,
            self.handle.clone(),
            self.category.clone(),
            self.sensitivity,
            self.tags.clone(),
            public_meta,
            version,
        )
        .map_err(|e| AppError::Domain(e.to_string()))?;

        let secret_id = secret.id;

        // 4. Persist.
        ctx.storage.put_secret(&secret).await?;

        // 5. Append audit entry.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Put,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .handle(self.handle.clone())
        .sensitivity(self.sensitivity)
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!(secret_id = %secret_id, "put_secret: secret persisted");
        Ok(PutSecretOutput {
            secret_id,
            handle: self.handle.clone(),
        })
    }
}
