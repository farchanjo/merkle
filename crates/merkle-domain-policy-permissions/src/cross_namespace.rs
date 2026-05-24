//! [`CrossNamespacePolicy`] — cross-namespace access control ValueObject.
//!
//! Mirrors `#CrossNamespace` in `docs/arch/schemas/policy_permissions/namespace_policy.cue`
//! and `docs/arch/policies/cross_namespace.rego`.

use serde::{Deserialize, Serialize};

use merkle_types::NamespaceLabel;

use crate::error::PolicyError;

/// Governs whether a session bound to one Namespace may access Secrets in
/// another Namespace.
///
/// Default posture is deny; a positive allowlist entry is required for each
/// permitted cross-namespace import (per `cross_namespace.rego` and ADR-0008).
///
/// ```
/// use merkle_domain_policy_permissions::cross_namespace::CrossNamespacePolicy;
/// use merkle_types::NamespaceLabel;
///
/// let session: NamespaceLabel = "acme-prod".parse().unwrap();
/// let target:  NamespaceLabel = "acme-prod".parse().unwrap();
///
/// // Same namespace always allowed.
/// let policy = CrossNamespacePolicy::default_deny();
/// assert!(policy.check(&session, &target).is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossNamespacePolicy {
    /// Master switch; when `false`, no cross-namespace access is permitted
    /// regardless of [`allowed_imports`](CrossNamespacePolicy::allowed_imports).
    pub master_switch: bool,
    /// Positive allowlist of target namespace labels from which Secrets may
    /// be imported into the session namespace.
    pub allowed_imports: Vec<NamespaceLabel>,
}

impl CrossNamespacePolicy {
    /// Default policy: cross-namespace access disabled.
    #[must_use]
    pub fn default_deny() -> Self {
        Self {
            master_switch: false,
            allowed_imports: vec![],
        }
    }

    /// Policy with master switch on and the given allowlist.
    #[must_use]
    pub fn with_imports(imports: Vec<NamespaceLabel>) -> Self {
        Self {
            master_switch: true,
            allowed_imports: imports,
        }
    }

    /// Evaluate whether a cross-namespace access from `session_label` to
    /// `target_label` is permitted by this policy.
    ///
    /// Rules (mirrors `cross_namespace.rego`):
    /// 1. Same namespace: always allow.
    /// 2. Empty label: deny.
    /// 3. Master switch off: deny all cross-namespace.
    /// 4. Master switch on but target not in allowlist: deny.
    /// 5. Master switch on and target in allowlist: allow.
    ///
    /// # Errors
    ///
    /// Returns a [`PolicyError`] describing the first denial rule that fires.
    pub fn check(
        &self,
        session_label: &NamespaceLabel,
        target_label: &NamespaceLabel,
    ) -> Result<(), PolicyError> {
        // Rule 1: same namespace.
        if session_label == target_label {
            return Ok(());
        }

        // Rule 2: empty labels — caught upstream by type validation; defensive
        // guard here for robustness.
        if session_label.as_str().is_empty() || target_label.as_str().is_empty() {
            return Err(PolicyError::EmptyNamespaceLabel);
        }

        // Rule 3: master switch off.
        if !self.master_switch {
            return Err(PolicyError::CrossNamespaceGloballyDisabled);
        }

        // Rule 4: target not in allowlist.
        if !self.allowed_imports.contains(target_label) {
            return Err(PolicyError::CrossNamespaceNotAllowed {
                target: target_label.to_string(),
            });
        }

        // Rule 5: allow.
        Ok(())
    }
}
