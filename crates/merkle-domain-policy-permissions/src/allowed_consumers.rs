//! [`AllowedConsumers`] — glob-based process-name allowlist ValueObject.
//!
//! Mirrors `docs/arch/schemas/policy_permissions/allowed_consumers.cue` and
//! the `allowed_consumers` field semantics described in
//! `docs/arch/domain/policy-permissions.md`.

use serde::{Deserialize, Serialize};

/// Glob allowlist of process names authorized to access a Namespace via the
/// Companion Socket.
///
/// Pattern semantics (Unix shell glob, NOT full glob library):
/// - `*` matches any sequence of characters (including the empty sequence).
/// - `?` matches exactly one character.
/// - Patterns do **not** match directory separators — they match the bare
///   process name, not a filesystem path.
/// - Matching is case-sensitive (follows Linux convention; see
///   `docs/arch/domain/policy-permissions.md` for macOS note).
///
/// An empty `globs` list denies all external consumers. A single `*` entry
/// permits any process name (the `relaxed` profile default).
///
/// ```
/// use merkle_domain_policy_permissions::allowed_consumers::AllowedConsumers;
///
/// let any = AllowedConsumers { globs: vec!["*".to_owned()] };
/// assert!(any.matches("curl"));
/// assert!(any.matches("my-app"));
///
/// let empty = AllowedConsumers { globs: vec![] };
/// assert!(!empty.matches("anything"));
///
/// let prefix = AllowedConsumers { globs: vec!["vault-*".to_owned()] };
/// assert!(prefix.matches("vault-agent"));
/// assert!(!prefix.matches("curl"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowedConsumers {
    /// Ordered list of glob patterns.
    ///
    /// Patterns are matched in order; the first match wins (allow). If no
    /// pattern matches, the consumer is denied.
    pub globs: Vec<String>,
}

impl AllowedConsumers {
    /// Default for the `relaxed` profile: any process is allowed.
    #[must_use]
    pub fn default_relaxed() -> Self {
        Self {
            globs: vec!["*".to_owned()],
        }
    }

    /// Default for the `balanced` profile: no consumers by default.
    ///
    /// Operators must explicitly configure the allowed processes for their
    /// namespace.
    #[must_use]
    pub fn default_balanced() -> Self {
        Self { globs: vec![] }
    }

    /// Default for the `paranoid` profile: no consumers allowed.
    #[must_use]
    pub fn default_paranoid() -> Self {
        Self { globs: vec![] }
    }

    /// Returns `true` when `program_path` matches at least one glob pattern.
    ///
    /// Implements Unix shell glob semantics inline: `*` = any chars, `?` = one
    /// char. Path separator matching is intentionally not supported — the
    /// intent is to match the bare process name, not a filesystem path.
    #[must_use]
    pub fn matches(&self, program_path: &str) -> bool {
        self.globs.iter().any(|pat| glob_match(pat, program_path))
    }
}

/// Minimal Unix-shell glob matcher supporting `*` (any run) and `?` (one char).
///
/// Does not use any external crate. Implementation uses iterative DP with
/// two cursors that avoids recursion.
fn glob_match(pattern: &str, input: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let hay: Vec<char> = input.chars().collect();
    let (p_len, h_len) = (pat.len(), hay.len());

    // dp[i][j] = true when pat[..i] matches hay[..j]
    // Use a flat bool matrix sized (p_len+1) × (h_len+1).
    let mut dp = vec![false; (p_len + 1) * (h_len + 1)];
    let idx = |i: usize, j: usize| i * (h_len + 1) + j;

    dp[idx(0, 0)] = true;

    // A leading `*` can match the empty haystack.
    for i in 1..=p_len {
        if pat[i - 1] == '*' {
            dp[idx(i, 0)] = dp[idx(i - 1, 0)];
        }
    }

    for i in 1..=p_len {
        for j in 1..=h_len {
            dp[idx(i, j)] = match pat[i - 1] {
                '*' => dp[idx(i - 1, j)] || dp[idx(i, j - 1)],
                '?' => dp[idx(i - 1, j - 1)],
                c => dp[idx(i - 1, j - 1)] && c == hay[j - 1],
            };
        }
    }

    dp[idx(p_len, h_len)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("curl", "curl"));
        assert!(!glob_match("curl", "curl2"));
    }

    #[test]
    fn glob_star_matches_any() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("vault-*", "vault-agent"));
        assert!(!glob_match("vault-*", "my-agent"));
    }

    #[test]
    fn glob_question_matches_one() {
        assert!(glob_match("cur?", "curl"));
        assert!(!glob_match("cur?", "cu"));
        assert!(!glob_match("cur?", "curll"));
    }

    #[test]
    fn allowed_consumers_empty_denies_all() {
        let ac = AllowedConsumers { globs: vec![] };
        assert!(!ac.matches("curl"));
    }

    #[test]
    fn allowed_consumers_star_permits_all() {
        let ac = AllowedConsumers::default_relaxed();
        assert!(ac.matches("curl"));
        assert!(ac.matches("my-custom-app"));
    }

    #[test]
    fn allowed_consumers_prefix_glob() {
        let ac = AllowedConsumers {
            globs: vec!["vault-*".to_owned(), "merkle-*".to_owned()],
        };
        assert!(ac.matches("vault-agent"));
        assert!(ac.matches("merkle-cli"));
        assert!(!ac.matches("curl"));
    }
}
