//! `GpgKeyCategory` — public metadata for `category = "gpg"` Secrets.

use serde::{Deserialize, Serialize};

/// GPG key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GpgAlgo {
    /// RSA 2048-bit.
    Rsa2048,
    /// RSA 3072-bit.
    Rsa3072,
    /// RSA 4096-bit.
    Rsa4096,
    /// Ed25519.
    Ed25519,
    /// Curve25519 (encryption subkey).
    Cv25519,
}

/// Metadata for a single GPG subkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubkeyInfo {
    /// Subkey ID (hex string).
    pub id: String,
    /// Algorithm name.
    pub algo: String,
    /// Usage flags (e.g. `"S"` for sign, `"E"` for encrypt).
    pub usage: String,
}

/// Public metadata fields for a `gpg` category Secret.
///
/// Maps the `#PublicMeta` shape from
/// `docs/arch/schemas/secret_storage/categories/gpg/gpg.cue`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpgKeyCategory {
    /// Long key ID (16-character hex) or fingerprint.
    pub key_id: String,

    /// Full 40-character fingerprint.
    pub fingerprint: String,

    /// User IDs associated with this key.
    pub uid: Vec<String>,

    /// Primary key algorithm.
    pub algo: GpgAlgo,

    /// Key creation timestamp (RFC 3339).
    pub created: String,

    /// Key expiry timestamp (RFC 3339), if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// Subkey descriptors.
    pub subkeys: Vec<SubkeyInfo>,
}
