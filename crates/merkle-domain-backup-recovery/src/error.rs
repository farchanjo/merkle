//! Domain errors for the Backup and Recovery bounded context.

use thiserror::Error;

/// Errors produced by the Backup and Recovery domain.
#[derive(Debug, Error)]
pub enum BackupError {
    /// The two backup recipients must be distinct (`MasterPubkey` ≠ `RecoveryPublicKey`).
    #[error("backup recipients must be distinct: both are {0:?}")]
    DuplicateRecipients(crate::recipient::BackupRecipient),

    /// A backup must contain at least one secret.
    #[error("backup secret_count must be greater than zero")]
    ZeroSecretCount,

    /// The `BackupArtifact` must have `encrypt_then_mac = true` per ADR-0006 Amendment.
    #[error("backup artifact must have encrypt_then_mac = true per ADR-0006")]
    EncryptThenMacNotSet,

    /// The restore plan has expired and can no longer be applied.
    #[error("restore plan {plan_id} expired at {expires_at}")]
    RestorePlanExpired {
        /// The plan identifier.
        plan_id: merkle_types::UuidV7,
        /// When the plan expired.
        expires_at: merkle_types::Rfc3339Timestamp,
    },
}
