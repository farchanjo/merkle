//! `CompanionSocketSession` — authenticated Companion Socket connection entity.

use merkle_types::{NamespaceLabel, Rfc3339Timestamp, UuidV7};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// An authenticated connection from an external process to the Companion Socket.
///
/// The Vault Agent authenticates each peer at `accept(2)` time using
/// `SO_PEERCRED` (Linux/macOS) or `GetNamedPipeClientProcessId` (Windows) to
/// obtain `peer_pid`.  `peer_program_path` is resolved from `/proc/<pid>/exe`
/// (Linux) or the platform equivalent.
///
/// Each session is bound to exactly one Namespace context; cross-Namespace
/// token resolution through a single session is not permitted.
/// [`CompanionSocketSession::bind_namespace`] enforces the single-binding
/// invariant.
///
/// ```
/// use merkle_types::{NamespaceLabel, Rfc3339Timestamp, UuidV7};
/// use merkle_domain_access_mediation::companion_socket_session::CompanionSocketSession;
///
/// let mut session = CompanionSocketSession {
///     id: UuidV7::new(),
///     peer_pid: 12345,
///     peer_program_path: "/usr/bin/git".into(),
///     bound_namespace: None,
///     allowlist_match: true,
///     started_at: Rfc3339Timestamp::now(),
/// };
/// session.bind_namespace("prod".parse().unwrap()).unwrap();
/// assert!(session.bound_namespace.is_some());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionSocketSession {
    /// UUIDv7 identifying this socket connection.
    pub id: UuidV7,
    /// OS process identifier of the connecting client.
    pub peer_pid: u32,
    /// Absolute executable path of the connecting process, resolved from
    /// `/proc/<pid>/exe` or platform equivalent.
    pub peer_program_path: String,
    /// Namespace the session is bound to, if [`bind_namespace`] has been called.
    ///
    /// [`bind_namespace`]: CompanionSocketSession::bind_namespace
    pub bound_namespace: Option<NamespaceLabel>,
    /// `true` when `peer_program_path` matched the Allowed Consumers glob list
    /// from the Namespace Policy at authentication time.
    pub allowlist_match: bool,
    /// RFC 3339 timestamp when the connection was accepted.
    pub started_at: Rfc3339Timestamp,
}

impl CompanionSocketSession {
    /// Bind this session to a Namespace.
    ///
    /// May only be called once per session.  A second call returns
    /// [`DomainError::NamespaceAlreadyBound`].
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::NamespaceAlreadyBound`] if the session already
    /// has a bound namespace.
    pub fn bind_namespace(&mut self, ns: NamespaceLabel) -> Result<(), DomainError> {
        if self.bound_namespace.is_some() {
            return Err(DomainError::NamespaceAlreadyBound);
        }
        self.bound_namespace = Some(ns);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_types::{NamespaceLabel, Rfc3339Timestamp, UuidV7};

    fn make_session() -> CompanionSocketSession {
        CompanionSocketSession {
            id: UuidV7::new(),
            peer_pid: 9999,
            peer_program_path: "/usr/bin/git".into(),
            bound_namespace: None,
            allowlist_match: true,
            started_at: Rfc3339Timestamp::now(),
        }
    }

    #[test]
    fn bind_namespace_once_succeeds() {
        let mut s = make_session();
        let ns: NamespaceLabel = "prod".parse().expect("parse ns");
        s.bind_namespace(ns.clone()).expect("first bind");
        assert_eq!(s.bound_namespace.as_ref(), Some(&ns));
    }

    #[test]
    fn bind_namespace_twice_is_error() {
        let mut s = make_session();
        let ns: NamespaceLabel = "prod".parse().expect("parse ns");
        s.bind_namespace(ns.clone()).expect("first bind");
        let err = s.bind_namespace(ns).expect_err("second bind should fail");
        assert!(matches!(err, DomainError::NamespaceAlreadyBound));
    }

    #[test]
    fn serde_json_round_trip() {
        let s = make_session();
        let json = serde_json::to_string(&s).expect("serialize");
        let back: CompanionSocketSession = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(s.id, back.id);
        assert_eq!(s.peer_pid, back.peer_pid);
    }
}
