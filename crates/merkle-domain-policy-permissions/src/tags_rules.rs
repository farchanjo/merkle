//! [`TagsRules`] — tag validation constraints ValueObject.
//!
//! Mirrors `#TagsRules` in `docs/arch/schemas/policy_permissions/namespace_policy.cue`
//! and the rules in `docs/arch/policies/tag_validation.rego`.

use serde::{Deserialize, Serialize};

use merkle_types::{Sensitivity, Tag, TagKey};

use crate::error::PolicyError;

/// Validation constraints on the tag set of a Secret in a given Namespace.
///
/// Three independent axes:
/// - [`required_keys`](TagsRules::required_keys): keys that every Secret must carry.
/// - [`allowed_keys`](TagsRules::allowed_keys): when non-empty, limits which keys are
///   accepted (any key not in this list is forbidden). When empty the closed-enum in
///   [`merkle_types::TagKey`] is the effective allowlist.
/// - [`forbidden_values`](TagsRules::forbidden_values): `(key, raw_value)` pairs that
///   must never appear.
///
/// Additionally, `sensitivity=high` Secrets must always carry an `env` tag,
/// regardless of the `required_keys` list (per `tag_validation.rego` Rule 3).
///
/// ```
/// use merkle_domain_policy_permissions::tags_rules::TagsRules;
/// use merkle_types::{Tag, TagKey, Sensitivity};
///
/// let rules = TagsRules {
///     required_keys: vec![TagKey::Env],
///     allowed_keys:  vec![],
///     forbidden_values: vec![],
/// };
/// let tags: Vec<Tag> = vec!["env:prod".parse().unwrap()];
/// assert!(rules.validate(&tags, Sensitivity::High).is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagsRules {
    /// Tag keys that every Secret in the Namespace must carry.
    pub required_keys: Vec<TagKey>,
    /// Supplemental allowlist. When non-empty, only listed keys are accepted.
    /// When empty, any key in the [`merkle_types::TagKey`] closed enum is accepted.
    pub allowed_keys: Vec<TagKey>,
    /// `(TagKey, raw_value_string)` pairs that are forbidden on any Secret.
    ///
    /// The raw string form is used because [`merkle_types::TagValue`] already
    /// validates slug format; forbidden values may include non-slug strings that
    /// operators want to block (e.g. `"none"`, `"undefined"`).
    pub forbidden_values: Vec<(TagKey, String)>,
}

impl TagsRules {
    /// Default for all profiles (no required keys, no forbidden values).
    #[must_use]
    pub fn default_empty() -> Self {
        Self {
            required_keys: vec![],
            allowed_keys: vec![],
            forbidden_values: vec![],
        }
    }

    /// Validate a tag set against this rule set.
    ///
    /// Checks performed (in order, mirroring `tag_validation.rego`):
    /// 1. Required keys present.
    /// 2. No forbidden values.
    /// 3. `sensitivity=high` requires an `env` tag.
    /// 4. No keys outside `allowed_keys` (when list is non-empty).
    ///
    /// Returns the first validation error encountered.
    ///
    /// # Errors
    ///
    /// Returns a [`PolicyError`] describing the first failing rule.
    pub fn validate(&self, tags: &[Tag], sensitivity: Sensitivity) -> Result<(), PolicyError> {
        // Rule 1: required keys present.
        for key in &self.required_keys {
            if !tags.iter().any(|t| &t.key == key) {
                return Err(PolicyError::RequiredTagMissing {
                    key: key.to_string(),
                });
            }
        }

        // Rule 2: forbidden values.
        for tag in tags {
            for (forbidden_key, forbidden_val) in &self.forbidden_values {
                if &tag.key == forbidden_key && tag.value.as_str() == forbidden_val {
                    return Err(PolicyError::ForbiddenTagValue {
                        key: tag.key.to_string(),
                        value: tag.value.to_string(),
                    });
                }
            }
        }

        // Rule 3: sensitivity=high requires env tag.
        if sensitivity == Sensitivity::High && !tags.iter().any(|t| t.key == TagKey::Env) {
            return Err(PolicyError::HighSensitivityMissingEnvTag);
        }

        // Rule 4: unknown keys when allowed_keys is non-empty.
        if !self.allowed_keys.is_empty() {
            for tag in tags {
                if !self.allowed_keys.contains(&tag.key) {
                    return Err(PolicyError::UnknownTagKey {
                        key: tag.key.to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}
