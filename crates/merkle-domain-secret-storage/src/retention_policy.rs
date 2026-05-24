//! `RetentionPolicy` — version retention rules for a Namespace.
//!
//! The default `retain_count` of **3** is specified in ADR-0014. When the
//! number of `SecretVersion` entries exceeds `retain_count`, the oldest
//! versions (lowest `version_no`) are pruned by marking `deprecated_at`.

use merkle_types::Rfc3339Timestamp;
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::secret_version::SecretVersion;

/// Default number of `SecretVersion` entries to retain per `Secret`.
pub const DEFAULT_RETAIN_COUNT: u32 = 3;

/// Governs how many historical `SecretVersion` entries are retained per `Secret`.
///
/// When `apply` is called after a rotation, excess oldest versions are pruned
/// by setting their `deprecated_at` timestamp. Physical deletion is deferred
/// to a vacuum pass.
///
/// # Invariants
///
/// - `retain_count >= 1`: a count of zero would immediately discard all versions,
///   which is rejected at construction time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Maximum number of `SecretVersion` entries to keep.
    ///
    /// Defaults to [`DEFAULT_RETAIN_COUNT`] (3). Must be at least 1.
    pub retain_count: u32,
}

impl RetentionPolicy {
    /// Construct a `RetentionPolicy` with the given `retain_count`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidRetainCount`] when `retain_count == 0`.
    pub fn new(retain_count: u32) -> Result<Self, DomainError> {
        if retain_count == 0 {
            return Err(DomainError::InvalidRetainCount(retain_count));
        }
        Ok(Self { retain_count })
    }

    /// Prune `versions` so that at most `retain_count` entries remain.
    ///
    /// The strategy is **oldest-first**: entries with the lowest `version_no`
    /// are removed first. Versions that are already deprecated (non-current)
    /// are removed before active versions.
    ///
    /// This operates on the in-memory aggregate state. The `StoragePort` is
    /// responsible for persisting the resulting slice (deleting the dropped
    /// rows from the database atomically).
    pub fn apply(&self, versions: &mut Vec<SecretVersion>) {
        let retain = self.retain_count as usize;

        if versions.len() <= retain {
            return;
        }

        // Sort ascending by version_no so the oldest are at the front.
        versions.sort_by_key(|v| v.version_no);

        // Mark excess as deprecated before removing, so callers can observe
        // the deprecation timestamp if they inspect before the vec is trimmed.
        let excess = versions.len() - retain;
        let now = Rfc3339Timestamp::now();
        for version in versions.iter_mut().take(excess) {
            if version.deprecated_at.is_none() {
                version.deprecated_at = Some(now);
            }
        }

        // Drop the oldest entries from the front.
        versions.drain(0..excess);
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            retain_count: DEFAULT_RETAIN_COUNT,
        }
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

    fn make_version(version_no: u32) -> SecretVersion {
        let handle = Handle::new(
            "my-ns".parse::<NamespaceLabel>().expect("valid"),
            "ssh".parse::<CategoryName>().expect("valid"),
            "my-key".parse::<SecretName>().expect("valid"),
        );
        let ad = handle.to_string().into_bytes();
        let blob = PrivateBlob::new(vec![1, 2, 3], [0u8; 24], [0u8; 16], ad, 1);
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
    fn rejects_zero_retain_count() {
        assert!(RetentionPolicy::new(0).is_err());
    }

    #[test]
    fn default_retain_count_is_three() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.retain_count, 3);
    }

    #[test]
    fn apply_noop_when_within_limit() {
        let policy = RetentionPolicy::default();
        let mut versions = vec![make_version(1), make_version(2)];
        policy.apply(&mut versions);
        assert!(versions.iter().all(|v| v.deprecated_at.is_none()));
    }

    #[test]
    fn apply_removes_oldest_on_excess() {
        let policy = RetentionPolicy::default(); // retain_count = 3
        let mut versions = vec![
            make_version(1),
            make_version(2),
            make_version(3),
            make_version(4),
            make_version(5),
        ];
        policy.apply(&mut versions);
        // Only 3 remain (versions 3, 4, 5); versions 1 and 2 are drained.
        assert_eq!(versions.len(), 3);
        let remaining_nos: Vec<u32> = versions.iter().map(|v| v.version_no).collect();
        assert_eq!(remaining_nos, vec![3, 4, 5]);
    }

    #[test]
    fn apply_with_retain_count_one() {
        let policy = RetentionPolicy::new(1).expect("valid");
        let mut versions = vec![make_version(1), make_version(2), make_version(3)];
        policy.apply(&mut versions);
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version_no, 3);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn apply_never_leaves_more_than_retain_count(
            n_versions in 1usize..=20usize,
            retain in 1u32..=10u32,
        ) {
            let policy = RetentionPolicy::new(retain).expect("valid");
            let n = u32::try_from(n_versions).expect("n_versions fits u32 in proptest range");
            let mut versions: Vec<SecretVersion> = (1..=n)
                .map(make_version)
                .collect();
            policy.apply(&mut versions);
            prop_assert!(versions.len() <= retain as usize);
        }

        #[test]
        fn apply_is_idempotent(
            n_versions in 1usize..=10usize,
            retain in 1u32..=5u32,
        ) {
            let policy = RetentionPolicy::new(retain).expect("valid");
            let n = u32::try_from(n_versions).expect("n_versions fits u32 in proptest range");
            let mut versions: Vec<SecretVersion> = (1..=n)
                .map(make_version)
                .collect();
            policy.apply(&mut versions);
            let len_after_first = versions.len();
            policy.apply(&mut versions);
            let len_after_second = versions.len();
            prop_assert_eq!(len_after_first, len_after_second);
        }
    }
}
