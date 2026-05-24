//! `SecretVersion` — a historical revision of a Secret's private material.
//!
//! Created automatically on every `vault.rotate` call. Immutable after
//! creation; rollback restores a historical blob by copying it into a new
//! current version.

use std::fmt;
use std::str::FromStr;

use merkle_types::{Rfc3339Timestamp, SecretId, UuidV7};
use serde::{Deserialize, Serialize};

use crate::private_blob::PrivateBlob;
use merkle_types::ParseError;

// ---------------------------------------------------------------------------
// SecretVersionId
// ---------------------------------------------------------------------------

/// A `UuidV7` scoped to the `SecretVersion` identity.
///
/// Defined locally because `merkle-types` does not expose a `SecretVersionId`
/// (Phase-1 scope decision).
///
/// ```
/// use merkle_domain_secret_storage::secret_version::SecretVersionId;
///
/// let id = SecretVersionId::new();
/// let s = id.to_string();
/// let parsed: SecretVersionId = s.parse().unwrap();
/// assert_eq!(id, parsed);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretVersionId(UuidV7);

impl SecretVersionId {
    /// Generate a fresh `SecretVersionId`.
    #[must_use]
    pub fn new() -> Self {
        Self(UuidV7::new())
    }

    /// Return the inner `UuidV7`.
    #[must_use]
    pub fn inner(&self) -> UuidV7 {
        self.0
    }
}

impl Default for SecretVersionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecretVersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretVersionId({self})")
    }
}

impl fmt::Display for SecretVersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for SecretVersionId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

impl TryFrom<&str> for SecretVersionId {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for SecretVersionId {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

// ---------------------------------------------------------------------------
// SecretVersion
// ---------------------------------------------------------------------------

/// One historical revision of a Secret's private material.
///
/// `SecretVersion` is an Entity: it has a stable identity (`id`) and is
/// compared by identity, not by value.
///
/// # Invariants
///
/// 1. `version_no` is monotonically increasing within its parent `Secret` and
///    is never reused.
/// 2. A `SecretVersion` is immutable after creation; rollback creates a new
///    version copying the historical blob.
/// 3. At most one version in the parent's list has `deprecated_at == None`
///    (the current active version).
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    /// Stable identity for this version entry.
    pub id: SecretVersionId,

    /// The `SecretId` of the parent `Secret`; never changes.
    pub secret_id: SecretId,

    /// 1-based revision counter; monotonically increasing per `Secret`.
    pub version_no: u32,

    /// The encrypted blob as it existed at this version.
    pub blob: PrivateBlob,

    /// The Namespace DEK version used to encrypt this version's blob.
    ///
    /// Stored redundantly here (also inside `blob.dek_version`) for fast
    /// querying without decrypting the blob envelope.
    pub dek_version: u32,

    /// Timestamp when this version was sealed.
    pub created_at: Rfc3339Timestamp,

    /// Timestamp when this version was superseded or invalidated.
    ///
    /// `None` means this is the current active version. Only one version per
    /// parent `Secret` may have `deprecated_at == None`.
    pub deprecated_at: Option<Rfc3339Timestamp>,
}

impl SecretVersion {
    /// Return `true` if this version is currently active (not deprecated).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.deprecated_at.is_none()
    }
}

impl PartialEq for SecretVersion {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for SecretVersion {}

impl fmt::Debug for SecretVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretVersion")
            .field("id", &self.id)
            .field("secret_id", &self.secret_id)
            .field("version_no", &self.version_no)
            .field("blob", &self.blob)
            .field("dek_version", &self.dek_version)
            .field("created_at", &self.created_at)
            .field("deprecated_at", &self.deprecated_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_blob::PrivateBlob;
    use merkle_types::{
        CategoryName, Handle, NamespaceLabel, Rfc3339Timestamp, SecretId, SecretName,
    };

    fn make_blob() -> PrivateBlob {
        let handle = Handle::new(
            "my-ns".parse::<NamespaceLabel>().expect("valid"),
            "ssh".parse::<CategoryName>().expect("valid"),
            "key-name".parse::<SecretName>().expect("valid"),
        );
        let ad = handle.to_string().into_bytes();
        PrivateBlob::new(vec![0u8; 8], [0u8; 24], [0u8; 16], ad, 1)
    }

    fn make_version(no: u32) -> SecretVersion {
        SecretVersion {
            id: SecretVersionId::new(),
            secret_id: SecretId::new(),
            version_no: no,
            blob: make_blob(),
            dek_version: 1,
            created_at: Rfc3339Timestamp::now(),
            deprecated_at: None,
        }
    }

    #[test]
    fn version_id_round_trip() {
        let id = SecretVersionId::new();
        let s = id.to_string();
        let parsed: SecretVersionId = s.parse().expect("valid v7");
        assert_eq!(id, parsed);
    }

    #[test]
    fn active_when_deprecated_at_is_none() {
        let v = make_version(1);
        assert!(v.is_active());
    }

    #[test]
    fn not_active_when_deprecated_at_is_set() {
        let mut v = make_version(1);
        v.deprecated_at = Some(Rfc3339Timestamp::now());
        assert!(!v.is_active());
    }

    #[test]
    fn equality_by_identity() {
        let v1 = make_version(1);
        let v2 = make_version(1); // different id
        assert_ne!(v1, v2);
        let v3 = v1.clone();
        assert_eq!(v1, v3);
    }

    #[test]
    fn debug_redacts_ciphertext() {
        let v = make_version(1);
        let debug = format!("{v:?}");
        assert!(debug.contains("PrivateBlob"), "must show PrivateBlob");
    }
}
