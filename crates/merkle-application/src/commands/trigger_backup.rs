//! `TriggerBackupCommand` — encrypt and persist a vault backup.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use merkle_domain_backup_recovery::{
    artifact::BackupArtifact, backup::Backup, recipient::BackupRecipient, trigger::BackupTrigger,
};
use merkle_domain_identity::KEYCHAIN_SERVICE;
use merkle_ports::AgeRecipient;
use merkle_types::{AuditOp, AuditOutcome, HmacSignature, NamespaceId, Rfc3339Timestamp, UuidV7};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};
use tracing::info;

use crate::backup_payload::encode_v2;
use crate::commands::init_vault::KEYCHAIN_ACCOUNT_VRK_RECOVERY;
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

        if self.master_pubkey_recipient.trim().is_empty()
            || self.recovery_pubkey_recipient.trim().is_empty()
        {
            return Err(AppError::InvalidInput(
                "backup recipients must not be empty".into(),
            ));
        }
        if self.master_pubkey_recipient == self.recovery_pubkey_recipient {
            return Err(AppError::InvalidInput(
                "backup requires distinct master and recovery age recipients".into(),
            ));
        }

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

        // 2. Prefer backup v2 (secrets + recovery-wrapped VRK) when the recovery
        //    blob exists; otherwise fall back to legacy v1 secrets-only array so
        //    tests and partial fixtures still produce dual-recipient artifacts.
        let plaintext = match ctx
            .keychain
            .retrieve(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_VRK_RECOVERY)
            .await
        {
            Ok(vrk_recovery_b64) => {
                let vrk_recovery_age = BASE64.decode(&vrk_recovery_b64).map_err(|e| {
                    AppError::Domain(format!(
                        "vrk-recovery keychain blob is not valid base64: {e}"
                    ))
                })?;
                let payload = encode_v2(vrk_recovery_age, secrets);
                serde_json::to_vec(&payload)
                    .map_err(|e| AppError::Domain(format!("serialization failed: {e}")))?
            }
            Err(merkle_ports::KeychainError::NotFound) => serde_json::to_vec(&secrets)
                .map_err(|e| AppError::Domain(format!("serialization failed: {e}")))?,
            Err(e) => return Err(AppError::Keychain(e)),
        };

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

        // 5. Persist the exact ciphertext that was MAC'd.  The temporary file
        // lives next to the target, so rename is atomic on a single filesystem.
        // We do this before recording metadata: a listed backup must always
        // have an artifact at its advertised path.
        persist_artifact_atomically(&self.output_path, &ciphertext)?;

        // 6. Build the Backup aggregate.
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

        // 7. Persist backup record.  Do not leave a discoverable, untracked
        // secret-bearing artifact when the metadata write fails.
        if let Err(error) = ctx.storage.put_backup(&backup).await {
            let _ = std::fs::remove_file(&self.output_path);
            return Err(error.into());
        }

        // 8. Audit.
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

/// Write a backup without ever publishing a partial ciphertext at `target`.
///
/// The output directory is deliberately required to exist.  Silently creating
/// it would give a security-sensitive artifact an implicit ownership and mode.
fn persist_artifact_atomically(target: &Path, ciphertext: &[u8]) -> Result<(), AppError> {
    let Some(parent) = target.parent() else {
        return Err(AppError::InvalidInput(
            "backup output path must have a parent directory".into(),
        ));
    };
    if !parent.is_dir() {
        return Err(AppError::InvalidInput(format!(
            "backup output directory does not exist: {}",
            parent.display()
        )));
    }
    if target.file_name().is_none() {
        return Err(AppError::InvalidInput(
            "backup output path must name a file".into(),
        ));
    }
    if target.exists() {
        return Err(AppError::InvalidInput(format!(
            "refusing to overwrite existing backup artifact: {}",
            target.display()
        )));
    }

    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        target.file_name().map_or_else(
            || "backup".into(),
            |name| name.to_string_lossy().into_owned()
        ),
        UuidV7::new()
    ));

    let result = (|| -> Result<(), std::io::Error> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(ciphertext)?;
        file.sync_all()?;
        std::fs::rename(&temporary, target)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.map_err(|error| {
        AppError::Domain(format!(
            "failed to persist backup artifact at {}: {error}",
            target.display()
        ))
    })
}
