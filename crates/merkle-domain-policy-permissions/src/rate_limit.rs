//! [`RateLimit`] and [`OpClass`] — per-class sliding-window rate-limit ValueObject.
//!
//! Mirrors `docs/arch/schemas/policy_permissions/rate_limit.cue` and
//! `docs/arch/policies/rate_limit.rego`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;

/// Closed enum of operation classes subject to rate limiting.
///
/// Mirrors `#RateLimitClass` in `rate_limit.cue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpClass {
    /// `vault.get` and `vault.describe` calls returning public metadata.
    PlaintextReads,
    /// Companion Socket dereferences of Use Tokens.
    UseTokenResolves,
    /// `vault.reveal` operations returning plaintext to the MCP transport.
    Reveals,
}

impl std::fmt::Display for OpClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlaintextReads => f.write_str("plaintext_reads"),
            Self::UseTokenResolves => f.write_str("use_token_resolves"),
            Self::Reveals => f.write_str("reveals"),
        }
    }
}

/// A single rate-limit configuration entry for one [`OpClass`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitEntry {
    /// Maximum number of operations permitted within `window_seconds`.
    pub max_count: u32,
    /// Width of the sliding window in seconds.
    pub window_seconds: u32,
}

/// Per-class sliding-window rate limits embedded in [`crate::NamespacePolicy`].
///
/// A namespace must configure all three [`OpClass`] entries; partial
/// configurations are rejected at validation time. A `max_count = 0` denies
/// all operations of that class unconditionally.
///
/// ```
/// use std::collections::HashMap;
/// use merkle_domain_policy_permissions::rate_limit::{OpClass, RateLimit, RateLimitEntry};
///
/// let rl = RateLimit::default_relaxed();
/// assert!(rl.check(OpClass::Reveals, 2, 60).is_ok());
/// assert!(rl.check(OpClass::Reveals, 60, 60).is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    /// Rate-limit entries keyed by operation class.
    pub per_class: HashMap<OpClass, RateLimitEntry>,
}

impl RateLimit {
    /// Default for the `relaxed` profile — generous limits.
    #[must_use]
    pub fn default_relaxed() -> Self {
        let mut map = HashMap::new();
        map.insert(
            OpClass::PlaintextReads,
            RateLimitEntry { max_count: 60, window_seconds: 60 },
        );
        map.insert(
            OpClass::UseTokenResolves,
            RateLimitEntry { max_count: 120, window_seconds: 60 },
        );
        map.insert(
            OpClass::Reveals,
            RateLimitEntry { max_count: 10, window_seconds: 60 },
        );
        Self { per_class: map }
    }

    /// Default for the `balanced` profile — moderate limits.
    #[must_use]
    pub fn default_balanced() -> Self {
        let mut map = HashMap::new();
        map.insert(
            OpClass::PlaintextReads,
            RateLimitEntry { max_count: 10, window_seconds: 60 },
        );
        map.insert(
            OpClass::UseTokenResolves,
            RateLimitEntry { max_count: 60, window_seconds: 60 },
        );
        map.insert(
            OpClass::Reveals,
            RateLimitEntry { max_count: 5, window_seconds: 60 },
        );
        Self { per_class: map }
    }

    /// Default for the `paranoid` profile — strict limits.
    #[must_use]
    pub fn default_paranoid() -> Self {
        let mut map = HashMap::new();
        map.insert(
            OpClass::PlaintextReads,
            RateLimitEntry { max_count: 5, window_seconds: 60 },
        );
        map.insert(
            OpClass::UseTokenResolves,
            RateLimitEntry { max_count: 30, window_seconds: 60 },
        );
        map.insert(
            OpClass::Reveals,
            RateLimitEntry { max_count: 2, window_seconds: 60 },
        );
        Self { per_class: map }
    }

    /// Check whether the observed `current_count` within `window_seconds`
    /// is within the configured budget for `class`.
    ///
    /// Returns `Ok(())` when within budget, or a [`PolicyError`] describing
    /// the denial reason.
    ///
    /// Mirrors the Rego rules in `rate_limit.rego`:
    /// - Rule 2: no entry configured → deny.
    /// - Rule 3: `count >= max_count` → deny (budget exhausted).
    /// - Rule 4: window mismatch → deny conservatively.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::RateLimitNotConfigured`] when no entry exists for
    /// `class`, [`PolicyError::RateLimitExceeded`] when the count meets or
    /// exceeds the maximum, and [`PolicyError::RateLimitWindowMismatch`] when
    /// the caller's window differs from the policy window.
    pub fn check(
        &self,
        class: OpClass,
        current_count: u32,
        window_seconds: u32,
    ) -> Result<(), PolicyError> {
        let entry = self.per_class.get(&class).ok_or_else(|| {
            PolicyError::RateLimitNotConfigured { class: class.to_string() }
        })?;

        if window_seconds != entry.window_seconds {
            return Err(PolicyError::RateLimitWindowMismatch {
                class: class.to_string(),
                observed: window_seconds,
                expected: entry.window_seconds,
            });
        }

        if current_count >= entry.max_count {
            return Err(PolicyError::RateLimitExceeded { class: class.to_string() });
        }

        Ok(())
    }
}
