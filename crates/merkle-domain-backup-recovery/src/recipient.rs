//! [`BackupRecipient`] — the two `age` recipient identities used when encrypting
//! a Backup (W1.A constraint: exactly `MasterPubkey` + `RecoveryPublicKey`).

use serde::{Deserialize, Serialize};

/// The two `age` recipient identities written into every Backup archive.
///
/// Per ADR-0006 and CUE schema `backup.cue`, every Backup MUST have exactly
/// two recipients and they MUST be distinct: one `MasterPubkey` and one
/// `RecoveryPublicKey`.  This guarantees that either key can independently
/// decrypt the archive.
///
/// ```
/// use merkle_domain_backup_recovery::recipient::BackupRecipient;
///
/// let a = BackupRecipient::MasterPubkey;
/// let b = BackupRecipient::RecoveryPublicKey;
/// assert_ne!(a, b);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupRecipient {
    /// The Master public key derived from the Master Key at unseal time.
    MasterPubkey,
    /// The Recovery Public Key stored in `config.toml`.
    RecoveryPublicKey,
}
