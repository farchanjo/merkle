//! `TriggerBackupCommand` — encrypt and persist a vault backup.

use merkle_domain_backup_recovery::{
    artifact::BackupArtifact, backup::Backup, recipient::BackupRecipient, trigger::BackupTrigger,
};
use merkle_ports::AgeRecipient;
use merkle_types::{AuditOp, AuditOutcome, HmacSignature, NamespaceId, Rfc3339Timestamp, UuidV7};
use std::path::PathBuf;
use tracing::info;

use crate::{AppContext, AppError};

/// Input for triggering a backup.
#[derive(Debug)]
pub struct TriggerBackupCommand {
    /// Namespace to back up.
    pub namespace_id: NamespaceId,

    /// What caused this backup (Manual, ChangeTriggered, etc.).
    pub trigger: BackupTrigger,

    /// `age` bech32 recipient string for the Master public key.
    pub master_pubkey_recipient: String,

    /// `age` bech32 recipient string for the Recovery public key.
    pub recovery_pubkey_recipient: String,

    /// Filesystem path where the backup artifact should be written.
    pub output_path: PathBuf,
}

/// Output of `TriggerBackupCommand`.
#[derive(Debug)]
pub struct TriggerBackupOutput {
    /// The persisted backup aggregate.
    pub backup: Backup,
}

impl TriggerBackupCommand {
    /// Execute trigger-backup.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::Storage`] — storage read or write failed.
    /// - [`AppError::Crypto`] — age encryption failed.
    /// - [`AppError::Domain`] — backup aggregate invariant violated.
    pub async fn execute(&self, ctx: &AppContext) -> Result<TriggerBackupOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(namespace = %self.namespace_id, "trigger_backup: gathering secrets");

        // 1. Collect all secrets in the namespace.
        let secrets = ctx
            .storage
            .list_secrets(&self.namespace_id, merkle_ports::SecretFilter::default())
            .await?;

        let secret_count = u32::try_from(secrets.len())
            .map_err(|_| AppError::InvalidInput("secret count overflows u32".into()))?;

        if secret_count == 0 {
            return Err(AppError::InvalidInput(
                "cannot back up an empty namespace".into(),
            ));
        }

        // 2. Serialize secrets for encryption.
        let plaintext = serde_json::to_vec(&secrets)
            .map_err(|e| AppError::Domain(format!("serialization failed: {e}")))?;

        // 3. age-encrypt for both recipients.
        let recipients = vec![
            AgeRecipient(self.master_pubkey_recipient.clone()),
            AgeRecipient(self.recovery_pubkey_recipient.clone()),
        ];
        let ciphertext = ctx.crypto.age_encrypt(&recipients, &plaintext)?;

        // 4. Compute HMAC over the ciphertext (encrypt-then-MAC, ADR-0006).
        let hmac_key = ctx.require_hmac_key().await?;
        let hmac = HmacSignature::compute(&hmac_key, &ciphertext);

        let size_bytes = u64::try_from(ciphertext.len())
            .map_err(|_| AppError::InvalidInput("ciphertext size overflows u64".into()))?;

        // 5. Build the Backup aggregate.
        //    BackupArtifact::new takes (path, age_format_version: u8, hmac_tag).
        let artifact = BackupArtifact::new(self.output_path.clone(), 1_u8, hmac);

        let snapshot_id = UuidV7::new();
        let backup = Backup::new(
            self.namespace_id,
            snapshot_id,
            self.trigger,
            [
                BackupRecipient::MasterPubkey,
                BackupRecipient::RecoveryPublicKey,
            ],
            artifact,
            hmac,
            size_bytes,
            secret_count,
            Rfc3339Timestamp::now(),
        )
        .map_err(|e| AppError::Domain(e.to_string()))?;

        // 6. Persist backup record.
        ctx.storage.put_backup(&backup).await?;

        // 7. Audit.
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Backup,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!("trigger_backup: backup complete");
        Ok(TriggerBackupOutput { backup })
    }
}
