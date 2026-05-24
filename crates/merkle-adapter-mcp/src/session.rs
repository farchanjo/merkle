//! Per-session state for the MCP adapter.
//!
//! Accumulates context that arrives incrementally over the life of one MCP
//! session (one Claude Code window = one server process). The session is
//! initialised empty and populated as the client issues tool calls.

use std::fmt;

use merkle_types::NamespaceId;

/// Per-session state: accumulates the namespace binding and session ID.
///
/// Created fresh for each `MerkleMcpServer` instance (one per MCP session).
/// Access is guarded by `tokio::sync::RwLock` on the `MerkleMcpServer`.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_field_names,
    reason = "All fields are genuinely namespace-scoped; the 'namespace_' prefix \
              disambiguates from future session fields (session_id, audit_context, etc.)"
)]
pub struct SessionState {
    /// Namespace label bound by `vault.bind`. `None` until `vault.bind` is
    /// called. Operations that require a Namespace return `NamespaceNotBound`
    /// when this field is `None`.
    pub namespace_label: Option<String>,

    /// The `NamespaceId` UUID returned by `BindNamespaceCommand`, stored after
    /// `vault.bind` succeeds. Used by all subsequent tool calls so they operate
    /// on the same namespace record that was created in storage.
    pub namespace_id: Option<NamespaceId>,

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

    /// Return the bound `NamespaceId`, or `None` if not yet bound.
    #[must_use]
    pub fn namespace_id(&self) -> Option<NamespaceId> {
        self.namespace_id
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

    /// Persist the `NamespaceId` returned by `BindNamespaceCommand`.
    ///
    /// Called immediately after a successful `vault.bind` to ensure all
    /// subsequent tool calls use the same namespace record from storage.
    pub fn set_namespace_id(&mut self, id: NamespaceId) {
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
