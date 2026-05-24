//! [`Backup`] — AggregateRoot representing one completed encrypted vault export.

use serde::{Deserialize, Serialize};

use merkle_types::{HmacSignature, NamespaceId, Rfc3339Timestamp, UuidV7};

use crate::{
    artifact::BackupArtifact,
    error::BackupError,
    recipient::BackupRecipient,
    trigger::BackupTrigger,
};

/// AggregateRoot for a single completed, encrypted vault export.
///
/// # Invariants
///
/// 1. `recipients[0] != recipients[1]`: the two recipients MUST be distinct —
///    one `MasterPubkey` and one `RecoveryPublicKey`.  This is enforced by
///    [`Backup::new`] and mirrors the CUE `backup.cue` disjunction.
/// 2. `secret_count > 0`: a Backup of an empty vault is rejected.
/// 3. `artifact.encrypt_then_mac == true`: enforced by [`BackupArtifact::new`].
/// 4. `hmac` is the BLAKE3 keyed MAC over the `age` *ciphertext* (encrypt-then-MAC
///    per ADR-0006 Amendment).
///
/// ```
/// use merkle_types::{HmacSignature, NamespaceId, Rfc3339Timestamp, UuidV7};
/// use std::path::PathBuf;
/// use merkle_domain_backup_recovery::{
///     artifact::BackupArtifact,
///     backup::Backup,
///     recipient::BackupRecipient,
///     trigger::BackupTrigger,
/// };
///
/// let key = [0u8; 32];
/// let hmac = HmacSignature::compute(&key, b"ciphertext");
/// let artifact = BackupArtifact::new(
///     PathBuf::from("/backups/merkle-bk-20260522T120000Z.merkle.age"),
///     1,
///     hmac,
/// );
/// let backup = Backup::new(
///     NamespaceId::new(),
///     UuidV7::new(),
///     BackupTrigger::Manual,
///     [BackupRecipient::MasterPubkey, BackupRecipient::RecoveryPublicKey],
///     artifact,
///     hmac,
///     1024,
///     10,
///     Rfc3339Timestamp::now(),
/// ).expect("valid backup");
/// assert_eq!(backup.secret_count, 10);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backup {
    /// Unique identifier for this backup record (UUIDv7).
    pub id: UuidV7,
    /// The namespace this backup belongs to.
    pub namespace_id: NamespaceId,
    /// The snapshot UUIDv7 corresponding to the SQLite Online Backup snapshot.
    pub snapshot_id: UuidV7,
    /// What caused this backup to be initiated.
    pub trigger: BackupTrigger,
    /// Exactly two distinct `age` recipients (MasterPubkey + RecoveryPublicKey).
    pub recipients: [BackupRecipient; 2],
    /// Descriptor of the on-disk artifact.
    pub artifact: BackupArtifact,
    /// BLAKE3 keyed MAC over the `age` *ciphertext* (encrypt-then-MAC, ADR-0006).
    pub hmac: HmacSignature,
    /// Size of the encrypted archive in bytes.
    pub size_bytes: u64,
    /// Number of secrets captured in this backup.
    pub secret_count: u32,
    /// When this backup was produced (UTC, RFC 3339).
    pub created_at: Rfc3339Timestamp,
}

impl Backup {
    /// Construct a validated [`Backup`] aggregate.
    ///
    /// # Errors
    ///
    /// - [`BackupError::DuplicateRecipients`] when both recipients are the same.
    /// - [`BackupError::ZeroSecretCount`] when `secret_count == 0`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        namespace_id: NamespaceId,
        snapshot_id: UuidV7,
        trigger: BackupTrigger,
        recipients: [BackupRecipient; 2],
        artifact: BackupArtifact,
        hmac: HmacSignature,
        size_bytes: u64,
        secret_count: u32,
        created_at: Rfc3339Timestamp,
    ) -> Result<Self, BackupError> {
        if recipients[0] == recipients[1] {
            return Err(BackupError::DuplicateRecipients(recipients[0]));
        }
        if secret_count == 0 {
            return Err(BackupError::ZeroSecretCount);
        }
        Ok(Self {
            id: UuidV7::new(),
            namespace_id,
            snapshot_id,
            trigger,
            recipients,
            artifact,
            hmac,
            size_bytes,
            secret_count,
            created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn dummy_hmac() -> HmacSignature {
        HmacSignature::compute(&[0u8; 32], b"ciphertext")
    }

    fn dummy_artifact() -> BackupArtifact {
        BackupArtifact::new(
            PathBuf::from("/tmp/merkle-bk-20260522T120000Z.merkle.age"),
            1,
            dummy_hmac(),
        )
    }

    fn make_backup(
        recipients: [BackupRecipient; 2],
        secret_count: u32,
    ) -> Result<Backup, BackupError> {
        Backup::new(
            NamespaceId::new(),
            UuidV7::new(),
            BackupTrigger::Manual,
            recipients,
            dummy_artifact(),
            dummy_hmac(),
            1024,
            secret_count,
            Rfc3339Timestamp::now(),
        )
    }

    #[test]
    fn valid_backup_succeeds() {
        let b = make_backup(
            [BackupRecipient::MasterPubkey, BackupRecipient::RecoveryPublicKey],
            5,
        );
        assert!(b.is_ok());
    }

    #[test]
    fn duplicate_recipients_master_rejected() {
        let err = make_backup(
            [BackupRecipient::MasterPubkey, BackupRecipient::MasterPubkey],
            5,
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::DuplicateRecipients(BackupRecipient::MasterPubkey)));
    }

    #[test]
    fn duplicate_recipients_recovery_rejected() {
        let err = make_backup(
            [BackupRecipient::RecoveryPublicKey, BackupRecipient::RecoveryPublicKey],
            5,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BackupError::DuplicateRecipients(BackupRecipient::RecoveryPublicKey)
        ));
    }

    #[test]
    fn zero_secret_count_rejected() {
        let err = make_backup(
            [BackupRecipient::MasterPubkey, BackupRecipient::RecoveryPublicKey],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, BackupError::ZeroSecretCount));
    }

    #[test]
    fn reversed_recipient_order_also_valid() {
        // [RecoveryPublicKey, MasterPubkey] is distinct — must be accepted.
        let b = make_backup(
            [BackupRecipient::RecoveryPublicKey, BackupRecipient::MasterPubkey],
            1,
        );
        assert!(b.is_ok());
    }

    #[test]
    fn serde_round_trip() {
        let b = make_backup(
            [BackupRecipient::MasterPubkey, BackupRecipient::RecoveryPublicKey],
            3,
        )
        .expect("valid backup");
        let json = serde_json::to_string(&b).expect("serialize");
        let decoded: Backup = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(b.id, decoded.id);
        assert_eq!(b.secret_count, decoded.secret_count);
    }
}
