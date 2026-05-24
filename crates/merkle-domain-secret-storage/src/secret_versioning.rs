//! `SecretVersioning` — pure domain service for rotation and retention logic.
//!
//! All functions are stateless and operate on slices or mutable `Vec`
//! references. No I/O, no async — this service encodes only domain rules.

use merkle_types::Handle;

use crate::error::DomainError;
use crate::retention_policy::RetentionPolicy;
use crate::secret_version::SecretVersion;

/// Pure domain service encapsulating `SecretVersion` lifecycle logic.
///
/// No state; all methods are free functions grouped under this type for
/// discoverability.
pub struct SecretVersioning;

impl SecretVersioning {
    /// Compute the next `version_no` for a new `SecretVersion`.
    ///
    /// Returns the current maximum `version_no` + 1, or `1` when the list
    /// is empty (first version).
    #[must_use]
    pub fn next_version_no(versions: &[SecretVersion]) -> u32 {
        versions
            .iter()
            .map(|v| v.version_no)
            .max()
            .map_or(1, |max| max.saturating_add(1))
    }

    /// Prune `versions` according to `policy`, deprecating the oldest entries
    /// beyond `retain_count`.
    ///
    /// Delegates directly to [`RetentionPolicy::apply`].
    pub fn prune(versions: &mut Vec<SecretVersion>, policy: &RetentionPolicy) {
        policy.apply(versions);
    }

    /// Validate that the Associated Data in `version.blob` matches the
    /// expected Handle URI.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::AdBindingMismatch`] when the blob's AD bytes
    /// differ from the UTF-8 encoding of `expected_handle`.
    pub fn validate_ad_for_version(
        version: &SecretVersion,
        expected_handle: &Handle,
    ) -> Result<(), DomainError> {
        version.blob.verify_ad(expected_handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_blob::PrivateBlob;
    use crate::secret_version::{SecretVersion, SecretVersionId};
    use merkle_types::{
        CategoryName, Handle, NamespaceLabel, Rfc3339Timestamp, SecretId, SecretName,
    };

    fn make_handle() -> Handle {
        Handle::new(
            "my-ns".parse::<NamespaceLabel>().expect("valid"),
            "ssh".parse::<CategoryName>().expect("valid"),
            "my-key".parse::<SecretName>().expect("valid"),
        )
    }

    fn make_version(handle: &Handle, version_no: u32) -> SecretVersion {
        let ad = handle.to_string().into_bytes();
        let blob = PrivateBlob::new(vec![0u8; 4], [0u8; 24], [0u8; 16], ad, 1);
        SecretVersion {
            id: SecretVersionId::new(),
            secret_id: SecretId::new(),
            version_no,
            blob,
            dek_version: 1,
            created_at: Rfc3339Timestamp::now(),
            deprecated_at: None,
        }
    }

    #[test]
    fn next_version_no_on_empty_list() {
        assert_eq!(SecretVersioning::next_version_no(&[]), 1);
    }

    #[test]
    fn next_version_no_increments_max() {
        let handle = make_handle();
        let versions = vec![make_version(&handle, 1), make_version(&handle, 3)];
        assert_eq!(SecretVersioning::next_version_no(&versions), 4);
    }

    #[test]
    fn prune_delegates_to_policy() {
        let handle = make_handle();
        let mut versions: Vec<SecretVersion> = (1..=5).map(|n| make_version(&handle, n)).collect();
        let policy = RetentionPolicy::default(); // retain 3
        SecretVersioning::prune(&mut versions, &policy);
        assert_eq!(versions.len(), 3);
    }

    #[test]
    fn validate_ad_succeeds_for_correct_handle() {
        let handle = make_handle();
        let version = make_version(&handle, 1);
        assert!(SecretVersioning::validate_ad_for_version(&version, &handle).is_ok());
    }

    #[test]
    fn validate_ad_fails_for_wrong_handle() {
        let handle = make_handle();
        let version = make_version(&handle, 1);
        let wrong_handle = Handle::new(
            "other-ns".parse::<NamespaceLabel>().expect("valid"),
            "ssh".parse::<CategoryName>().expect("valid"),
            "my-key".parse::<SecretName>().expect("valid"),
        );
        assert!(SecretVersioning::validate_ad_for_version(&version, &wrong_handle).is_err());
    }
}
