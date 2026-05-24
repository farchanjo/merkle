//! `Fifo` — named-pipe Secret materialization entity.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A named-pipe variant of [`crate::tempfile::Tempfile`] that delivers Secret
/// material exactly once on the first read, then removes itself.
///
/// Suitable for tools that consume credentials by filesystem path but never
/// re-read (e.g., `ssh -i <path>`, GnuPG `--passphrase-file`).
///
/// ## Invariants
///
/// 1. The FIFO is removed after the first successful read.
/// 2. If no process reads within the session TTL, the orphan reaper cleans it
///    up using the same path as Tempfile reaping.
/// 3. The `real_path_redacted` field is never serialized to the MCP transport
///    and is redacted in `Debug` output.
///
/// ```
/// use std::path::PathBuf;
/// use merkle_domain_access_mediation::fifo::Fifo;
///
/// let fifo = Fifo {
///     opaque_token: "fifo_abc123".into(),
///     real_path_redacted: PathBuf::from("/run/user/1000/merkle/cred.fifo"),
///     consumed: false,
/// };
/// let debug = format!("{fifo:?}");
/// assert!(debug.contains("REDACTED"));
/// assert!(!fifo.consumed);
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct Fifo {
    /// Opaque server-side token returned to the MCP transport.
    pub opaque_token: String,
    /// Actual named-pipe filesystem path — private, never crosses the MCP boundary.
    #[serde(skip)]
    pub real_path_redacted: PathBuf,
    /// `true` after the first successful read has been detected.
    pub consumed: bool,
}

impl fmt::Debug for Fifo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fifo")
            .field("opaque_token", &self.opaque_token)
            .field("real_path_redacted", &"REDACTED")
            .field("consumed", &self.consumed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fifo() -> Fifo {
        Fifo {
            opaque_token: "fifo_test_001".into(),
            real_path_redacted: PathBuf::from("/run/user/1000/merkle/id_rsa.fifo"),
            consumed: false,
        }
    }

    #[test]
    fn starts_not_consumed() {
        assert!(!make_fifo().consumed);
    }

    #[test]
    fn debug_redacts_real_path() {
        let f = make_fifo();
        let debug = format!("{f:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("id_rsa.fifo"));
    }

    #[test]
    fn serde_skips_real_path() {
        let f = make_fifo();
        let json = serde_json::to_string(&f).expect("serialize");
        assert!(!json.contains("id_rsa.fifo"), "path must not serialize");
        let back: Fifo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(f.opaque_token, back.opaque_token);
        assert_eq!(back.real_path_redacted, PathBuf::new());
    }
}
