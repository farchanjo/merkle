//! On-disk backup plaintext formats (Feature 002 restore + Feature 003 DR).
//!
//! - **v1** — bare JSON array of [`Secret`] aggregates (legacy).
//! - **v2** — object with recovery-wrapped VRK age blob + secrets, so disaster
//!   recovery on a wiped keychain can re-wrap the Vault Root Key.

use merkle_domain_secret_storage::Secret;
use serde::{Deserialize, Serialize};

/// Format marker for dual-recipient backups that include the recovery-wrapped VRK.
pub const BACKUP_FORMAT_V2: &str = "merkle-backup-v2";

/// Versioned backup plaintext after age decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BackupPlaintext {
    /// Legacy: secrets only (cannot recover VRK on a wiped keychain).
    V1(Vec<Secret>),
    /// Current: recovery-wrapped VRK + secrets.
    V2(BackupPayloadV2),
}

/// Backup payload that supports disaster recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPayloadV2 {
    /// Must be [`BACKUP_FORMAT_V2`].
    pub format: String,
    /// Raw age ciphertext of the 32-byte Vault Root Key under the recovery recipient.
    pub vrk_recovery_age: Vec<u8>,
    /// Full secret aggregates (including private version history).
    pub secrets: Vec<Secret>,
}

impl BackupPlaintext {
    /// Decode plaintext bytes produced by a dual-recipient age decrypt.
    ///
    /// # Errors
    ///
    /// Returns a string description when the JSON is neither v1 nor v2.
    pub fn decode(plaintext: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(plaintext).map_err(|e| format!("backup payload is not valid JSON: {e}"))
    }

    /// Secrets carried by either format.
    #[must_use]
    pub fn secrets(&self) -> &[Secret] {
        match self {
            Self::V1(secrets) | Self::V2(BackupPayloadV2 { secrets, .. }) => secrets,
        }
    }

    /// Recovery-wrapped VRK age ciphertext, if this is a v2 backup.
    #[must_use]
    pub fn vrk_recovery_age(&self) -> Option<&[u8]> {
        match self {
            Self::V1(_) => None,
            Self::V2(v2) => Some(v2.vrk_recovery_age.as_slice()),
        }
    }
}

/// Build a v2 payload for a new backup.
#[must_use]
pub fn encode_v2(vrk_recovery_age: Vec<u8>, secrets: Vec<Secret>) -> BackupPayloadV2 {
    BackupPayloadV2 {
        format: BACKUP_FORMAT_V2.to_owned(),
        vrk_recovery_age,
        secrets,
    }
}
