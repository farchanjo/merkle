//! `Secret` — the primary AggregateRoot for the Secret Storage bounded context.
//!
//! A `Secret` groups a credential artifact with its full version history,
//! public metadata, and classification attributes. All invariants listed in
//! `docs/arch/domain/secret-storage.md` and the CUE schemas are enforced at
//! construction time and at mutation boundaries.
//!
//! # Invariants enforced by this type
//!
//! 1. `handle.category` must match `category`.
//! 2. `versions` is never empty.
//! 3. `current_version_id` references an existing entry in `versions`.
//! 4. At most one version has `deprecated_at == None`.
//! 5. `sensitivity = High` requires at least one `env:*` Tag.
//! 6. `public_metadata.expose` must be `false` when `sensitivity = High`.
//! 7. No duplicate `key:value` tag pairs.

use merkle_types::{
    CategoryName, Handle, NamespaceId, Rfc3339Timestamp, SecretId, Sensitivity, Tag, TagKey,
};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::public_metadata::PublicMetadata;
use crate::retention_policy::RetentionPolicy;
use crate::secret_version::{SecretVersion, SecretVersionId};
use crate::secret_versioning::SecretVersioning;

/// The primary AggregateRoot for a stored credential.
///
/// Construct via [`Secret::new`]; rotate via [`Secret::rotate`].
/// Direct field mutation outside these methods bypasses invariant checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    /// Stable UUIDv7 primary key; immutable after creation.
    pub id: SecretId,

    /// The owning `Namespace` identifier.
    pub namespace_id: NamespaceId,

    /// Opaque URI — `vault://<ns>/<cat>/<name>`.
    pub handle: Handle,

    /// Category; immutable after creation.
    pub category: CategoryName,

    /// Sensitivity level.
    pub sensitivity: Sensitivity,

    /// Structured `key:value` discriminators.
    pub tags: Vec<Tag>,

    /// Publicly-visible metadata snapshot.
    pub public_metadata: PublicMetadata,

    /// RFC 3339 creation timestamp.
    pub created_at: Rfc3339Timestamp,

    /// All historical versions, including the current one.
    ///
    /// Private to prevent bypassing the invariant checks enforced by
    /// [`Secret::rotate`].
    versions: Vec<SecretVersion>,

    /// Identity of the currently active version.
    current_version_id: SecretVersionId,
}

impl Secret {
    /// Construct a new `Secret`, validating all invariants.
    ///
    /// The supplied `initial_version` becomes the sole entry in the version
    /// list and is immediately set as the current version.
    ///
    /// # Errors
    ///
    /// - [`DomainError::HandleCategoryMismatch`] — `handle.category` does not
    ///   match `category`.
    /// - [`DomainError::HighSensitivityMissingEnvTag`] — `sensitivity = High`
    ///   without an `env:*` Tag.
    /// - [`DomainError::ExposeOnHighSensitivity`] — `public_metadata.expose =
    ///   true` on a `High` sensitivity Secret.
    /// - [`DomainError::DuplicateTag`] — duplicate `key:value` pair in `tags`.
    pub fn new(
        namespace_id: NamespaceId,
        handle: Handle,
        category: CategoryName,
        sensitivity: Sensitivity,
        tags: Vec<Tag>,
        public_metadata: PublicMetadata,
        initial_version: SecretVersion,
    ) -> Result<Self, DomainError> {
        // Invariant 1: handle.category must match category.
        if handle.category().to_string() != category.to_string() {
            return Err(DomainError::HandleCategoryMismatch {
                handle: handle.category().to_string(),
                secret: category.to_string(),
            });
        }

        // Invariant 7: no duplicate tags.
        Self::check_no_duplicate_tags(&tags)?;

        // Invariant 5: high sensitivity requires env:* tag.
        if sensitivity == Sensitivity::High && !tags.iter().any(|t| t.key == TagKey::Env) {
            return Err(DomainError::HighSensitivityMissingEnvTag);
        }

        // Invariant 6: expose must be false for high sensitivity.
        if sensitivity == Sensitivity::High && public_metadata.expose {
            return Err(DomainError::ExposeOnHighSensitivity);
        }

        let current_version_id = initial_version.id;

        Ok(Self {
            id: SecretId::new(),
            namespace_id,
            handle,
            category,
            sensitivity,
            tags,
            public_metadata,
            created_at: Rfc3339Timestamp::now(),
            versions: vec![initial_version],
            current_version_id,
        })
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Return an immutable slice of all versions (including deprecated).
    #[must_use]
    pub fn versions(&self) -> &[SecretVersion] {
        &self.versions
    }

    /// Return the identity of the current active version.
    #[must_use]
    pub fn current_version_id(&self) -> SecretVersionId {
        self.current_version_id
    }

    /// Return the current active `SecretVersion`, or `None` when the list is
    /// somehow inconsistent (should not occur in practice).
    #[must_use]
    pub fn current_version(&self) -> Option<&SecretVersion> {
        self.versions
            .iter()
            .find(|v| v.id == self.current_version_id)
    }

    // -----------------------------------------------------------------------
    // Mutation — rotate
    // -----------------------------------------------------------------------

    /// Rotate the secret: append `new_version`, deprecate the current version,
    /// and apply the retention policy.
    ///
    /// Returns a shared reference to the newly active version.
    ///
    /// # Errors
    ///
    /// - [`DomainError::NonMonotonicVersionNumber`] — the new version's
    ///   `version_no` is not strictly greater than the current maximum.
    /// - [`DomainError::CurrentVersionNotFound`] — the internal consistency
    ///   invariant for `current_version_id` is violated (should be unreachable
    ///   in correct usage).
    pub fn rotate(
        &mut self,
        new_version: SecretVersion,
        policy: &RetentionPolicy,
    ) -> Result<&SecretVersion, DomainError> {
        // Invariant: version_no must be monotonically increasing.
        let current_max = self
            .versions
            .iter()
            .map(|v| v.version_no)
            .max()
            .unwrap_or(0);

        if new_version.version_no <= current_max {
            return Err(DomainError::NonMonotonicVersionNumber {
                current: current_max,
                new: new_version.version_no,
            });
        }

        let new_version_id = new_version.id;
        let now = Rfc3339Timestamp::now();

        // Deprecate the currently active version.
        let old_id = self.current_version_id;
        match self.versions.iter_mut().find(|v| v.id == old_id) {
            Some(v) => {
                if v.deprecated_at.is_none() {
                    v.deprecated_at = Some(now);
                }
            }
            None => {
                return Err(DomainError::CurrentVersionNotFound(old_id.to_string()));
            }
        }

        // Append the new version.
        self.versions.push(new_version);
        self.current_version_id = new_version_id;

        // Apply retention policy (prunes oldest deprecated versions).
        SecretVersioning::prune(&mut self.versions, policy);

        // Return reference to the new current version.
        let idx = self
            .versions
            .iter()
            .position(|v| v.id == new_version_id)
            .expect("just pushed; must be present");

        Ok(&self.versions[idx])
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn check_no_duplicate_tags(tags: &[Tag]) -> Result<(), DomainError> {
        // O(n^2) — tag lists are tiny (< 20 items in practice).
        for (i, t) in tags.iter().enumerate() {
            for t2 in tags.iter().skip(i + 1) {
                if t == t2 {
                    return Err(DomainError::DuplicateTag(t.to_string()));
                }
            }
        }
        Ok(())
    }
}

// `PartialEq` by identity (aggregate root semantics).
impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Secret {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_blob::PrivateBlob;
    use merkle_types::{CategoryName, Handle, NamespaceId, NamespaceLabel, SecretName, TagValue};

    fn make_handle(ns: &str, cat: &str, name: &str) -> Handle {
        Handle::new(
            ns.parse::<NamespaceLabel>().expect("valid ns"),
            cat.parse::<CategoryName>().expect("valid cat"),
            name.parse::<SecretName>().expect("valid name"),
        )
    }

    fn make_blob(handle: &Handle) -> PrivateBlob {
        let ad = handle.to_string().into_bytes();
        PrivateBlob::new(vec![0u8; 8], [0u8; 24], [0u8; 16], ad, 1)
    }

    fn make_version(handle: &Handle, version_no: u32) -> SecretVersion {
        SecretVersion {
            id: SecretVersionId::new(),
            secret_id: SecretId::new(),
            version_no,
            blob: make_blob(handle),
            dek_version: 1,
            created_at: Rfc3339Timestamp::now(),
            deprecated_at: None,
        }
    }

    fn env_tag() -> Tag {
        Tag {
            key: TagKey::Env,
            value: "prod".parse::<TagValue>().expect("valid"),
        }
    }

    #[test]
    fn new_secret_happy_path() {
        let handle = make_handle("my-ns", "ssh", "my-key");
        let v = make_version(&handle, 1);
        let s = Secret::new(
            NamespaceId::new(),
            handle.clone(),
            CategoryName::SshKey,
            Sensitivity::Medium,
            vec![],
            PublicMetadata::default(),
            v,
        )
        .expect("valid");

        assert_eq!(s.versions().len(), 1);
        assert!(s.current_version().is_some());
    }

    #[test]
    fn rejects_handle_category_mismatch() {
        let handle = make_handle("my-ns", "ssh", "my-key");
        let v = make_version(&handle, 1);
        let result = Secret::new(
            NamespaceId::new(),
            handle,
            CategoryName::Password, // mismatch: handle says "ssh"
            Sensitivity::Low,
            vec![],
            PublicMetadata::default(),
            v,
        );
        assert!(matches!(
            result,
            Err(DomainError::HandleCategoryMismatch { .. })
        ));
    }

    #[test]
    fn rejects_high_sensitivity_without_env_tag() {
        let handle = make_handle("my-ns", "ssh", "my-key");
        let v = make_version(&handle, 1);
        let result = Secret::new(
            NamespaceId::new(),
            handle,
            CategoryName::SshKey,
            Sensitivity::High,
            vec![], // no env:* tag
            PublicMetadata::default(),
            v,
        );
        assert!(matches!(
            result,
            Err(DomainError::HighSensitivityMissingEnvTag)
        ));
    }

    #[test]
    fn rejects_expose_on_high_sensitivity() {
        let handle = make_handle("my-ns", "ssh", "my-key");
        let v = make_version(&handle, 1);
        let result = Secret::new(
            NamespaceId::new(),
            handle,
            CategoryName::SshKey,
            Sensitivity::High,
            vec![env_tag()],
            PublicMetadata::new(true), // expose = true
            v,
        );
        assert!(matches!(result, Err(DomainError::ExposeOnHighSensitivity)));
    }

    #[test]
    fn rejects_duplicate_tags() {
        let handle = make_handle("my-ns", "ssh", "my-key");
        let v = make_version(&handle, 1);
        let tag = env_tag();
        let result = Secret::new(
            NamespaceId::new(),
            handle,
            CategoryName::SshKey,
            Sensitivity::High,
            vec![tag.clone(), tag],
            PublicMetadata::default(),
            v,
        );
        assert!(matches!(result, Err(DomainError::DuplicateTag(_))));
    }

    #[test]
    fn high_sensitivity_with_env_tag_accepted() {
        let handle = make_handle("my-ns", "ssh", "my-key");
        let v = make_version(&handle, 1);
        let s = Secret::new(
            NamespaceId::new(),
            handle,
            CategoryName::SshKey,
            Sensitivity::High,
            vec![env_tag()],
            PublicMetadata::default(),
            v,
        )
        .expect("should accept");
        assert_eq!(s.sensitivity, Sensitivity::High);
    }

    #[test]
    fn rotate_appends_and_deprecates_old() {
        let handle = make_handle("my-ns", "ssh", "my-key");
        let v1 = make_version(&handle, 1);
        let mut s = Secret::new(
            NamespaceId::new(),
            handle.clone(),
            CategoryName::SshKey,
            Sensitivity::Medium,
            vec![],
            PublicMetadata::default(),
            v1,
        )
        .expect("valid");

        let v2 = make_version(&handle, 2);
        let policy = RetentionPolicy::default();
        s.rotate(v2, &policy).expect("rotate ok");

        assert_eq!(s.versions().len(), 2);
        let active: Vec<u32> = s
            .versions()
            .iter()
            .filter(|v| v.deprecated_at.is_none())
            .map(|v| v.version_no)
            .collect();
        assert_eq!(active, vec![2]);
    }

    #[test]
    fn rotate_rejects_non_monotonic_version_no() {
        let handle = make_handle("my-ns", "ssh", "my-key");
        let v1 = make_version(&handle, 5);
        let mut s = Secret::new(
            NamespaceId::new(),
            handle.clone(),
            CategoryName::SshKey,
            Sensitivity::Medium,
            vec![],
            PublicMetadata::default(),
            v1,
        )
        .expect("valid");

        let v_old = make_version(&handle, 3); // version_no <= 5
        let policy = RetentionPolicy::default();
        let result = s.rotate(v_old, &policy);
        assert!(matches!(
            result,
            Err(DomainError::NonMonotonicVersionNumber { .. })
        ));
    }

    #[test]
    fn rotate_applies_retention_policy() {
        let handle = make_handle("my-ns", "ssh", "my-key");
        let v1 = make_version(&handle, 1);
        let mut s = Secret::new(
            NamespaceId::new(),
            handle.clone(),
            CategoryName::SshKey,
            Sensitivity::Medium,
            vec![],
            PublicMetadata::default(),
            v1,
        )
        .expect("valid");

        let policy = RetentionPolicy::new(2).expect("valid");

        for no in 2..=5_u32 {
            let v = make_version(&handle, no);
            s.rotate(v, &policy).expect("rotate");
        }

        // With retain_count = 2, after 4 rotations the vec is bounded to 2 entries.
        assert_eq!(
            s.versions().len(),
            2,
            "retain_count=2 bounds total vec to 2"
        );
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn rotate_invariant_exactly_one_active(n_rotations in 1usize..=15usize) {
            let handle = make_handle("my-ns", "ssh", "my-key");
            let v1 = make_version(&handle, 1);
            let mut s = Secret::new(
                NamespaceId::new(),
                handle.clone(),
                CategoryName::SshKey,
                Sensitivity::Medium,
                vec![],
                PublicMetadata::default(),
                v1,
            ).expect("valid");

            let policy = RetentionPolicy::default();
            let max_no = u32::try_from(n_rotations).expect("fits u32") + 1;
            for no in 2..=max_no {
                let v = make_version(&handle, no);
                s.rotate(v, &policy).expect("rotate");
            }

            let active = s.versions().iter().filter(|v| v.deprecated_at.is_none()).count();
            prop_assert_eq!(active, 1, "exactly one version must be active after rotations");
        }

        #[test]
        fn rotate_version_count_bounded_by_retain(
            n_rotations in 1usize..=20usize,
            retain in 1u32..=5u32,
        ) {
            let handle = make_handle("my-ns", "ssh", "my-key");
            let v1 = make_version(&handle, 1);
            let mut s = Secret::new(
                NamespaceId::new(),
                handle.clone(),
                CategoryName::SshKey,
                Sensitivity::Medium,
                vec![],
                PublicMetadata::default(),
                v1,
            ).expect("valid");

            let policy = RetentionPolicy::new(retain).expect("valid");
            let max_no = u32::try_from(n_rotations).expect("fits u32") + 1;
            for no in 2..=max_no {
                let v = make_version(&handle, no);
                s.rotate(v, &policy).expect("rotate");
            }

            prop_assert!(
                s.versions().len() <= retain as usize,
                "total versions {} must not exceed retain_count {}",
                s.versions().len(),
                retain,
            );
        }
    }
}
