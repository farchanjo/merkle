//! Per-session state for the MCP adapter.
//!
//! Accumulates context that arrives incrementally over the life of one MCP
//! session (one Claude Code window = one server process). The session is
//! initialised empty and populated as the client issues tool calls.

use std::fmt;

use uuid::Uuid;

/// Per-session state: accumulates the namespace binding, session ID, and
/// other context built up as the client issues tool calls.
///
/// Created fresh for each `MerkleMcpServer` instance (one per MCP session).
/// Access is guarded by `tokio::sync::RwLock` on the `MerkleMcpServer`.
#[derive(Debug, Default)]
pub struct SessionState {
    /// Namespace label bound by `vault.bind`. `None` until `vault.bind` is
    /// called. Operations that require a Namespace return `NamespaceNotBound`
    /// when this field is `None`.
    pub namespace_label: Option<String>,

    /// The `namespace_id` UUID returned by `CreateSessionResponse`, stored after
    /// `vault.bind` succeeds. Used by all subsequent tool calls so they operate
    /// on the same namespace record that was created in storage.
    pub namespace_id: Option<Uuid>,

    /// The `session_id` UUID returned by `POST /v1/sessions` (`CreateSessionResponse`).
    /// Required by `vault.reveal` (`RevealRequest.session_id`) and the use-token
    /// endpoints (`UseTokenRequest.session_id`, etc.) so all requests within a
    /// session are correlated server-side.
    pub session_id: Option<Uuid>,

    /// Whether the namespace has been bound in this session.
    /// Enforces the "at most one bind per session" invariant.
    pub namespace_bound: bool,
}

impl SessionState {
    /// Return the bound namespace label, or `None` if not yet bound.
    #[must_use]
    pub fn namespace_label(&self) -> Option<&str> {
        self.namespace_label.as_deref()
    }

    /// Return the bound `namespace_id` UUID, or `None` if not yet bound.
    #[must_use]
    pub fn namespace_id(&self) -> Option<Uuid> {
        self.namespace_id
    }

    /// Return the server-assigned `session_id`, or `None` before `vault.bind`.
    #[must_use]
    pub fn session_id(&self) -> Option<Uuid> {
        self.session_id
    }

    /// Record a namespace binding. Returns `Err` if already bound.
    ///
    /// # Errors
    ///
    /// Returns `"AlreadyBound"` message string when `vault.bind` has already
    /// been called in this session.
    pub fn bind(&mut self, label: String) -> Result<(), &'static str> {
        if self.namespace_bound {
            return Err("AlreadyBound: session already bound to a Namespace");
        }
        self.namespace_label = Some(label);
        self.namespace_bound = true;
        Ok(())
    }

    /// Persist the `namespace_id` and `session_id` returned by `POST /v1/sessions`.
    ///
    /// Called immediately after a successful `vault.bind` to ensure all
    /// subsequent tool calls use the same namespace record and session correlation
    /// from storage.
    pub fn set_binding(&mut self, namespace_id: Uuid, session_id: Uuid) {
        self.namespace_id = Some(namespace_id);
        self.session_id = Some(session_id);
    }

    /// Persist the `namespace_id` alone (backwards-compat helper).
    pub fn set_namespace_id(&mut self, id: Uuid) {
        self.namespace_id = Some(id);
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.namespace_label {
            Some(label) => write!(f, "SessionState(bound={label})"),
            None => write!(f, "SessionState(unbound)"),
        }
    }
}
