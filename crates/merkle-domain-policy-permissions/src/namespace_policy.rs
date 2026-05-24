//! [`NamespacePolicy`] — AggregateRoot of the PolicyPermissions bounded context.

use serde::{Deserialize, Serialize};

use merkle_types::{NamespaceId, Rfc3339Timestamp, SecurityProfile, UuidV7};

use crate::{
    allowed_consumers::AllowedConsumers,
    argon2id_floor::Argon2idMinFloor,
    cross_namespace::CrossNamespacePolicy,
    device_policy::DevicePolicy,
    rate_limit::RateLimit,
    retention::RetentionPolicy,
    reveal_policy::RevealPolicy,
    tags_rules::TagsRules,
    unseal_preconditions::UnsealPreconditionsPolicy,
};

/// The authoritative policy record for one Namespace.
///
/// AggregateRoot of the PolicyPermissions bounded context. Persisted
/// alongside the Namespace record; loaded into the Vault Agent's policy
/// cache on Unseal and invalidated on any write to the policy record.
///
/// Construct via [`NamespacePolicy::defaults_for`] and then selectively
/// override fields.
///
/// ```
/// use merkle_domain_policy_permissions::namespace_policy::NamespacePolicy;
/// use merkle_types::SecurityProfile;
///
/// let policy = NamespacePolicy::defaults_for(SecurityProfile::Balanced);
/// assert!(policy.reveal.allowed);
/// assert_eq!(policy.retention.retain_count, 3);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespacePolicy {
    /// Policy record identifier (UUIDv7).
    pub id: UuidV7,
    /// The Namespace this policy governs.
    pub namespace_id: NamespaceId,
    /// Security profile this policy was initialized from.
    pub security_profile: SecurityProfile,
    /// Reveal authorization rules.
    pub reveal: RevealPolicy,
    /// Per-class sliding-window rate limits.
    pub rate_limit: RateLimit,
    /// Process-name allowlist for Companion Socket consumers.
    pub allowed_consumers: AllowedConsumers,
    /// Tag validation constraints.
    pub tags_rules: TagsRules,
    /// Secret Version retention policy.
    pub retention: RetentionPolicy,
    /// Cross-namespace import policy.
    pub cross_namespace: CrossNamespacePolicy,
    /// Argon2id parameter floor (enforced in Identity context at unseal).
    pub argon2id_floor: Argon2idMinFloor,
    /// Companion device class requirement for Reveal operations.
    pub device_policy: DevicePolicy,
    /// Unseal pre-flight requirements.
    pub unseal_preconditions: UnsealPreconditionsPolicy,
    /// When this policy record was created.
    pub created_at: Rfc3339Timestamp,
}

impl NamespacePolicy {
    /// Construct a `NamespacePolicy` with sensible per-profile defaults.
    ///
    /// The returned policy is fully functional as-is; callers may override
    /// individual fields after construction to diverge from the profile
    /// baseline (per invariant 7 in `policy-permissions.md`).
    ///
    /// Uses a placeholder `UuidV7::new_unchecked` for the id and
    /// namespace_id. Production callers should supply real identifiers from
    /// the storage layer.
    #[must_use]
    pub fn defaults_for(profile: SecurityProfile) -> Self {
        use merkle_types::{NamespaceId, UuidV7};

        let id = UuidV7::new();
        let namespace_id = NamespaceId::new();
        let now = Rfc3339Timestamp::now();

        match profile {
            SecurityProfile::Relaxed => Self {
                id,
                namespace_id,
                security_profile: SecurityProfile::Relaxed,
                reveal: RevealPolicy::default_relaxed(),
                rate_limit: RateLimit::default_relaxed(),
                allowed_consumers: AllowedConsumers::default_relaxed(),
                tags_rules: TagsRules::default_empty(),
                retention: RetentionPolicy::default(),
                cross_namespace: CrossNamespacePolicy::default_deny(),
                argon2id_floor: Argon2idMinFloor::default(),
                device_policy: DevicePolicy {
                    required_class: merkle_types::CompanionDeviceClass::Software,
                },
                unseal_preconditions: UnsealPreconditionsPolicy::for_profile(
                    SecurityProfile::Relaxed,
                ),
                created_at: now,
            },
            SecurityProfile::Balanced => Self {
                id,
                namespace_id,
                security_profile: SecurityProfile::Balanced,
                reveal: RevealPolicy::default_balanced(),
                rate_limit: RateLimit::default_balanced(),
                allowed_consumers: AllowedConsumers::default_balanced(),
                tags_rules: TagsRules::default_empty(),
                retention: RetentionPolicy::default(),
                cross_namespace: CrossNamespacePolicy::default_deny(),
                argon2id_floor: Argon2idMinFloor::default(),
                device_policy: DevicePolicy::default(),
                unseal_preconditions: UnsealPreconditionsPolicy::for_profile(
                    SecurityProfile::Balanced,
                ),
                created_at: now,
            },
            SecurityProfile::Paranoid => Self {
                id,
                namespace_id,
                security_profile: SecurityProfile::Paranoid,
                reveal: RevealPolicy::default_paranoid(),
                rate_limit: RateLimit::default_paranoid(),
                allowed_consumers: AllowedConsumers::default_paranoid(),
                tags_rules: TagsRules::default_empty(),
                retention: RetentionPolicy::default(),
                cross_namespace: CrossNamespacePolicy::default_deny(),
                argon2id_floor: Argon2idMinFloor::default(),
                device_policy: DevicePolicy {
                    required_class: merkle_types::CompanionDeviceClass::HardwareToken,
                },
                unseal_preconditions: UnsealPreconditionsPolicy::for_profile(
                    SecurityProfile::Paranoid,
                ),
                created_at: now,
            },
        }
    }
}
