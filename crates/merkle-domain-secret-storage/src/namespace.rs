//! `Namespace` — the top-level container for related Secrets.
//!
//! A `Namespace` is identified by a stable `UuidV7` primary key and a
//! DNS-safe label. The label is immutable after creation; renaming requires
//! creating a new `Namespace`. The `cwd_hash` field is present only when the
//! namespace is bound to a working directory (ADR-0008).

use merkle_types::{NamespaceId, NamespaceLabel, Rfc3339Timestamp, UuidV7};
use serde::{Deserialize, Serialize};

/// The top-level container grouping related Secrets.
///
/// `Namespace` is an Entity: stable identity is `id`.
///
/// # Invariants
///
/// 1. `label` is immutable after creation; renaming creates a new `Namespace`.
/// 2. A `Namespace` without a provisioned `NamespaceDek` rejects all write
///    operations; DEK provisioning is handled by the IdentityAndSealing context.
/// 3. Cross-`Namespace` reads require an explicit import allowlist in the
///    governing `NamespacePolicy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Namespace {
    /// Stable UUIDv7 primary key; immutable after creation.
    pub id: NamespaceId,

    /// Stable human-readable identifier; unique per vault.
    pub label: NamespaceLabel,

    /// SHA-256 hex digest of the bound working directory path at bind time.
    ///
    /// Present only when this namespace is bound to a directory (ADR-0008).
    /// `None` for global or label-only bindings.
    pub cwd_hash: Option<String>,

    /// Reference to the governing `NamespacePolicy` in the PolicyPermissions
    /// bounded context. `None` means the vault-wide default policy applies.
    pub policy_id: Option<UuidV7>,

    /// Active Namespace DEK version used for new writes.
    ///
    /// Incremented whenever the DEK is rotated. Must be >= 1 before any
    /// write is accepted.
    pub dek_version: u32,

    /// RFC 3339 timestamp of namespace creation.
    pub created_at: Rfc3339Timestamp,
}

impl Namespace {
    /// Construct a new `Namespace` with the given label and initial DEK version.
    ///
    /// `cwd_hash` and `policy_id` are left as `None`; set them after
    /// construction if needed.
    #[must_use]
    pub fn new(label: NamespaceLabel, dek_version: u32) -> Self {
        Self {
            id: NamespaceId::new(),
            label,
            cwd_hash: None,
            policy_id: None,
            dek_version,
            created_at: Rfc3339Timestamp::now(),
        }
    }

    /// Return `true` when this namespace is bound to a specific working directory.
    #[must_use]
    pub fn is_cwd_bound(&self) -> bool {
        self.cwd_hash.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_types::NamespaceLabel;

    fn label(s: &str) -> NamespaceLabel {
        s.parse().expect("valid label")
    }

    #[test]
    fn new_creates_with_correct_label_and_dek() {
        let ns = Namespace::new(label("my-project"), 1);
        assert_eq!(ns.label.as_str(), "my-project");
        assert_eq!(ns.dek_version, 1);
        assert!(ns.cwd_hash.is_none());
        assert!(ns.policy_id.is_none());
    }

    #[test]
    fn cwd_bound_detection() {
        let mut ns = Namespace::new(label("my-project"), 1);
        assert!(!ns.is_cwd_bound());
        ns.cwd_hash = Some("abc123".into());
        assert!(ns.is_cwd_bound());
    }

    #[test]
    fn serde_round_trip() {
        let ns = Namespace {
            id: NamespaceId::new(),
            label: label("vault-prod"),
            cwd_hash: Some("deadbeef0011".into()),
            policy_id: None,
            dek_version: 2,
            created_at: Rfc3339Timestamp::now(),
        };
        let json = serde_json::to_string(&ns).expect("serialize");
        let parsed: Namespace = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ns, parsed);
    }
}
