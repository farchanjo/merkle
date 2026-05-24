//! [`BackupArtifact`] — filesystem artifact produced by a Backup operation.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use merkle_types::HmacSignature;

/// Describes the on-disk artifact for a completed Backup.
///
/// The `encrypt_then_mac` flag MUST always be `true` per the ADR-0006
/// Amendment: the HMAC is applied to the `age` ciphertext after encryption,
/// and the restore path MUST verify it before attempting decryption.
///
/// ```
/// use std::path::PathBuf;
/// use merkle_types::HmacSignature;
/// use merkle_domain_backup_recovery::artifact::BackupArtifact;
///
/// let key = [0u8; 32];
/// let tag = HmacSignature::compute(&key, b"ciphertext");
/// let a = BackupArtifact::new(PathBuf::from("/backups/merkle-bk-20260522T120000Z.merkle.age"), 1, tag);
/// assert!(a.encrypt_then_mac);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupArtifact {
    /// Local filesystem path of the `.merkle.age` file.
    pub path: PathBuf,
    /// `age` format version.  Currently `1`.
    pub age_format_version: u8,
    /// Always `true`: HMAC is computed over the `age` ciphertext (encrypt-then-MAC).
    pub encrypt_then_mac: bool,
    /// 32-byte BLAKE3 keyed MAC over the entire ciphertext, stored as a trailer.
    pub hmac_tag: HmacSignature,
}

impl BackupArtifact {
    /// Construct a [`BackupArtifact`], enforcing the encrypt-then-MAC invariant.
    ///
    /// The `encrypt_then_mac` field is always forced to `true`; the caller
    /// supplies the `hmac_tag` computed over the full ciphertext bytes.
    pub fn new(path: PathBuf, age_format_version: u8, hmac_tag: HmacSignature) -> Self {
        Self {
            path,
            age_format_version,
            encrypt_then_mac: true,
            hmac_tag,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tag() -> HmacSignature {
        HmacSignature::compute(&[0u8; 32], b"ciphertext")
    }

    #[test]
    fn encrypt_then_mac_always_true() {
        let a = BackupArtifact::new(
            PathBuf::from("/tmp/merkle-bk-20260522T120000Z.merkle.age"),
            1,
            dummy_tag(),
        );
        assert!(a.encrypt_then_mac, "encrypt_then_mac must always be true");
    }

    #[test]
    fn serde_round_trip() {
        let a = BackupArtifact::new(
            PathBuf::from("/tmp/test.merkle.age"),
            1,
            dummy_tag(),
        );
        let json = serde_json::to_string(&a).expect("serialize");
        let b: BackupArtifact = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(a, b);
    }
}
