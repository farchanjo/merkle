//! `PublicMetadata` — fields safe to return through the MCP transport.
//!
//! No field in `PublicMetadata` contains or references private (plaintext)
//! credential material. These fields appear in `vault.list` and
//! `vault.describe` responses and may appear in the LLM transcript.

use merkle_types::Rfc3339Timestamp;
use serde::{Deserialize, Serialize};

/// The publicly-visible metadata snapshot for a Secret.
///
/// # Invariants
///
/// - No field contains or is derived from the Secret's plaintext material.
/// - `expose = true` is forbidden for `Sensitivity::High` secrets; the
///   `Secret::new` constructor enforces this via [`crate::error::DomainError::ExposeOnHighSensitivity`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicMetadata {
    /// Optional operator commentary safe for the LLM transcript.
    ///
    /// Must never contain credentials or key material.
    pub description: Option<String>,

    /// Whether the Handle (plus public metadata) may be returned by default
    /// in list responses without an explicit describe call.
    ///
    /// Forbidden to be `true` when `sensitivity = high`. Enforced at the
    /// `Secret` aggregate level.
    pub expose: bool,

    /// Optional FTS5 keywords supplementing the built-in indexed fields.
    ///
    /// These are concatenated into the FTS5 `description` column at insert
    /// time, as specified in ADR-0013.
    pub fts_keywords: Option<Vec<String>>,

    /// Optional expiry timestamp for this Secret.
    ///
    /// When set and elapsed, the vault background job may retire the Secret.
    pub expires_at: Option<Rfc3339Timestamp>,

    /// Visible prefix of the secret value (e.g. `"ghp_"` for a GitHub PAT).
    ///
    /// Useful for disambiguation; must not exceed 8 characters per policy.
    pub prefix: Option<String>,

    /// Last four characters of the secret value.
    ///
    /// Useful for identifying which card or token is being operated on.
    pub last4: Option<String>,

    /// Public digest identifying key material without revealing it.
    ///
    /// Format is key-type-specific (e.g. `"SHA256:<base64>"` for SSH keys).
    pub fingerprint: Option<String>,
}

impl PublicMetadata {
    /// Construct `PublicMetadata` with only `expose` required; all other
    /// fields default to `None`.
    #[must_use]
    pub fn new(expose: bool) -> Self {
        Self {
            description: None,
            expose,
            fts_keywords: None,
            expires_at: None,
            prefix: None,
            last4: None,
            fingerprint: None,
        }
    }

    /// Return `true` when this metadata does not expose the Handle by default.
    #[must_use]
    pub fn is_private(&self) -> bool {
        !self.expose
    }
}

impl Default for PublicMetadata {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_expose_is_false() {
        let m = PublicMetadata::default();
        assert!(!m.expose);
        assert!(m.is_private());
    }

    #[test]
    fn new_expose_true_exposes() {
        let m = PublicMetadata::new(true);
        assert!(m.expose);
        assert!(!m.is_private());
    }

    #[test]
    fn serde_round_trip() {
        let m = PublicMetadata {
            description: Some("prod API key".into()),
            expose: false,
            fts_keywords: Some(vec!["production".into(), "api".into()]),
            expires_at: None,
            prefix: Some("ghp_".into()),
            last4: Some("ab12".into()),
            fingerprint: Some("SHA256:abc".into()),
        };
        let json = serde_json::to_string(&m).expect("serialize");
        let parsed: PublicMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m, parsed);
    }
}
