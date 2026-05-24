//! `Tempfile` — on-disk Secret materialization entity.

use std::fmt;
use std::path::PathBuf;

use merkle_types::Rfc3339Timestamp;
use serde::{Deserialize, Serialize};

/// A Secret materialized as a regular file on disk with mode `0600`.
///
/// Per the W4.B threat model and ADR-0011 fix, the `opaque_token` field is
/// the only identifier returned to the MCP transport.  It is a server-side
/// mapping key — NOT a real filesystem path.  The `real_path_redacted` field
/// holds the actual path but is:
/// - Never serialized to the MCP transport (skipped by serde).
/// - Redacted in the `Debug` implementation.
///
/// ## Reaping
///
/// Tempfiles are removed on:
/// 1. MCP Session close.
/// 2. Idle timeout (`expires_at` elapsed).
/// 3. Explicit `vault.revoke_tempfile`.
/// 4. Agent boot orphan reaper sweep.
///
/// ```
/// use std::path::PathBuf;
/// use merkle_types::Rfc3339Timestamp;
/// use merkle_domain_access_mediation::tempfile::Tempfile;
///
/// let tf = Tempfile {
///     opaque_token: "tok_abc123".into(),
///     real_path_redacted: PathBuf::from("/run/user/1000/merkle/abc"),
///     mode: 0o600,
///     expires_at: Rfc3339Timestamp::now(),
/// };
/// // real_path_redacted is NOT in the Debug output.
/// let debug = format!("{tf:?}");
/// assert!(debug.contains("REDACTED"));
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct Tempfile {
    /// Opaque server-side token returned to the MCP transport.  Callers
    /// reference tempfiles by this token, not by path.
    pub opaque_token: String,
    /// Actual filesystem path — private, never crosses the MCP boundary.
    #[serde(skip)]
    pub real_path_redacted: PathBuf,
    /// Unix permission bits; always `0o600`.
    pub mode: u32,
    /// RFC 3339 expiration timestamp.
    pub expires_at: Rfc3339Timestamp,
}

impl fmt::Debug for Tempfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tempfile")
            .field("opaque_token", &self.opaque_token)
            .field("real_path_redacted", &"REDACTED")
            .field("mode", &format_args!("{:#o}", self.mode))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tempfile() -> Tempfile {
        Tempfile {
            opaque_token: "tok_test_001".into(),
            real_path_redacted: PathBuf::from("/run/user/1000/merkle/secret.tmp"),
            mode: 0o600,
            expires_at: Rfc3339Timestamp::now(),
        }
    }

    #[test]
    fn mode_is_0600() {
        assert_eq!(make_tempfile().mode, 0o600);
    }

    #[test]
    fn debug_redacts_real_path() {
        let tf = make_tempfile();
        let debug = format!("{tf:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("merkle/secret.tmp"));
    }

    #[test]
    fn serde_skips_real_path() {
        let tf = make_tempfile();
        let json = serde_json::to_string(&tf).expect("serialize");
        assert!(
            !json.contains("merkle/secret.tmp"),
            "path must not serialize"
        );
        // Deserialize; real_path_redacted should be default (empty PathBuf).
        let back: Tempfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tf.opaque_token, back.opaque_token);
        assert_eq!(back.real_path_redacted, PathBuf::new());
    }
}
