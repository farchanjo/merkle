//! Domain error types for the Secret Storage bounded context.

use thiserror::Error;

/// All errors that can arise within the Secret Storage domain.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DomainError {
    /// The `Handle.category` does not match the `Secret.category`.
    #[error("handle category mismatch: handle has `{handle}`, secret has `{secret}`")]
    HandleCategoryMismatch {
        /// Category from the handle.
        handle: String,
        /// Category from the secret.
        secret: String,
    },

    /// The version list is empty; a Secret must have at least one version.
    #[error("secret must have at least one version")]
    EmptyVersionList,

    /// The `current_version_id` does not reference any entry in `versions`.
    #[error("current_version_id `{0}` is not present in the version list")]
    CurrentVersionNotFound(String),

    /// More than one version has `deprecated_at == None` (invariant: only the
    /// current version may be active).
    #[error("invariant violated: multiple active (non-deprecated) versions found")]
    MultipleActiveVersions,

    /// A `sensitivity = high` Secret was created without an `env:*` Tag.
    #[error("sensitivity = high requires at least one tag with key `env`")]
    HighSensitivityMissingEnvTag,

    /// `PublicMetadata.expose = true` was set on a `sensitivity = high` Secret.
    #[error("expose = true is forbidden for sensitivity = high secrets")]
    ExposeOnHighSensitivity,

    /// The Associated Data binding check failed: the AD bytes in the blob do
    /// not match the expected handle URI.
    #[error("AD binding mismatch: expected handle URI `{expected}`, got different bytes")]
    AdBindingMismatch {
        /// The expected handle URI string.
        expected: String,
    },

    /// The retention policy `retain_count` is zero, which would immediately
    /// discard all versions.
    #[error("retain_count must be >= 1 (got {0})")]
    InvalidRetainCount(u32),

    /// A rotation was attempted but the new version number is not strictly
    /// greater than the current maximum.
    #[error("new version_no `{new}` must be greater than current maximum `{current}`")]
    NonMonotonicVersionNumber {
        /// Current maximum version number.
        current: u32,
        /// Attempted new version number.
        new: u32,
    },

    /// Rollback requested a version number that is not present in history.
    #[error("target version `{version_no}` not found in secret history")]
    TargetVersionNotFound {
        /// Requested historical version number.
        version_no: u32,
    },

    /// A duplicate tag was supplied (same `key:value` pair appears twice).
    #[error("duplicate tag: `{0}`")]
    DuplicateTag(String),
}
