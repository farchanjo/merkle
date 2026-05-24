//! MCP error mapping.
//!
//! Maps [`ClientError`](merkle_companion_client::ClientError) values returned by
//! the Companion Socket into structured `rmcp::ErrorData` instances with the
//! numeric codes defined in `mcp-protocol.md` Section 4.

use merkle_companion_client::{ClientError, ProblemDetail};
use rmcp::{ErrorData, model::ErrorCode};

/// Well-known MCP application error codes (Section 4 of mcp-protocol.md).
pub mod codes {
    /// Vault is sealed; call `vault.unseal` first.
    pub const UNSEAL_REQUIRED: i32 = -32001;
    /// Request rate limit exceeded.
    pub const RATE_LIMIT_EXCEEDED: i32 = -32002;
    /// Reveal denied by policy.
    pub const REVEAL_DENIED: i32 = -32003;
    /// Secret handle not found.
    pub const HANDLE_NOT_FOUND: i32 = -32004;
    /// Session has no Namespace binding; call `vault.bind` first.
    pub const NAMESPACE_NOT_BOUND: i32 = -32005;
    /// Out-of-band confirmation is required.
    pub const OOB_CONFIRMATION_REQUIRED: i32 = -32006;
    /// Out-of-band confirmation timed out.
    pub const OOB_CONFIRMATION_TIMEOUT: i32 = -32007;
    /// Session is already bound to a Namespace.
    pub const ALREADY_BOUND: i32 = -32008;
    /// Schema validation failed.
    pub const SCHEMA_VALIDATION_FAILED: i32 = -32009;
    /// A secret with this name already exists.
    pub const DUPLICATE_NAME: i32 = -32010;
    /// SSH authentication failed.
    pub const SSH_AUTH_FAILED: i32 = -32020;
    /// SSH connection failed.
    pub const SSH_CONNECTION_FAILED: i32 = -32021;
    /// HTTP request failed.
    pub const HTTP_REQUEST_FAILED: i32 = -32030;
    /// Process spawn failed.
    pub const SPAWN_FAILED: i32 = -32040;
    /// Command timed out.
    pub const COMMAND_TIMEOUT: i32 = -32041;
    /// Tempfile creation failed.
    pub const TEMPFILE_CREATE_FAILED: i32 = -32050;
    /// Tool is scaffolded but not yet implemented (server returned 501).
    pub const TOOL_NOT_IMPLEMENTED: i32 = -32099;
    /// Agent is unreachable over the Companion Socket.
    pub const AGENT_UNREACHABLE: i32 = -32100;
    /// Protocol-level JSON error.
    pub const PROTOCOL_ERROR: i32 = -32101;
    /// Client build / request construction error.
    pub const CLIENT_BUILD_ERROR: i32 = -32102;
    /// Access denied (403).
    pub const ACCESS_DENIED: i32 = -32103;
    /// Resource conflict (409).
    pub const CONFLICT: i32 = -32104;
    /// Bad request (400).
    pub const BAD_REQUEST: i32 = -32105;
    /// Service temporarily unavailable (503).
    pub const SERVICE_UNAVAILABLE: i32 = -32106;
    /// Generic server error.
    pub const SERVER_ERROR: i32 = -32603;
}

// ---------------------------------------------------------------------------
// Primary mapping: ClientError → ErrorData
// ---------------------------------------------------------------------------

/// Map a [`ClientError`] into an `rmcp::ErrorData`.
///
/// The `problem_type` slug from RFC 7807 responses is forwarded verbatim as
/// the `error_type` data field when present, enabling callers to inspect the
/// semantic error without parsing the human-readable message.
///
/// # Code mapping
///
/// | ClientError variant | Status | Code constant |
/// |---|---|---|
/// | `Sealed` | — | `UNSEAL_REQUIRED` |
/// | `Http { status: 404, .. }` | 404 | `HANDLE_NOT_FOUND` |
/// | `Http { status: 403, .. }` | 403 | `ACCESS_DENIED` |
/// | `Http { status: 401, .. }` | 401 | `UNSEAL_REQUIRED` |
/// | `Http { status: 409, .. }` | 409 | `CONFLICT` |
/// | `Http { status: 400, .. }` | 400 | `BAD_REQUEST` |
/// | `Http { status: 501, .. }` | 501 | `TOOL_NOT_IMPLEMENTED` |
/// | `Http { status: 503, .. }` | 503 | `SERVICE_UNAVAILABLE` |
/// | `Http { .. }` | other | derived from `problem_type` slug |
/// | `Json(_)` | — | `PROTOCOL_ERROR` |
/// | `Unreachable(_)` | — | `AGENT_UNREACHABLE` |
/// | `Build(_)` | — | `CLIENT_BUILD_ERROR` |
pub fn client_error_to_mcp(err: ClientError) -> ErrorData {
    match err {
        ClientError::Sealed => ErrorData::new(
            ErrorCode(codes::UNSEAL_REQUIRED),
            "vault is sealed — call vault.unseal first",
            Some(serde_json::json!({
                "hint": "Run `merkle unseal` or configure Touch ID",
                "error_type": "vault.sealed",
            })),
        ),

        ClientError::Http {
            status,
            ref problem,
        } => http_problem_to_mcp(status, problem),

        ClientError::Json(e) => ErrorData::new(
            ErrorCode(codes::PROTOCOL_ERROR),
            format!("protocol error: {e}"),
            Some(serde_json::json!({
                "hint": "Check agent version compatibility",
                "error_type": "vault.protocol_error",
            })),
        ),

        ClientError::Unreachable(msg) => ErrorData::new(
            ErrorCode(codes::AGENT_UNREACHABLE),
            format!("vault agent unreachable: {msg}"),
            Some(serde_json::json!({
                "hint": "Check that the Vault Agent is running (`merkle status`)",
                "error_type": "vault.agent_unreachable",
            })),
        ),

        ClientError::Build(e) => ErrorData::new(
            ErrorCode(codes::CLIENT_BUILD_ERROR),
            format!("client build error: {e}"),
            Some(serde_json::json!({
                "hint": "This is an internal adapter error; report it",
                "error_type": "vault.client_build_error",
            })),
        ),
    }
}

/// Convert an HTTP status + RFC 7807 problem detail into an `ErrorData`.
fn http_problem_to_mcp(status: u16, problem: &ProblemDetail) -> ErrorData {
    let (code, error_type, hint) = classify_http(status, &problem.problem_type);
    let detail = if problem.detail.is_empty() {
        problem.title.clone()
    } else {
        format!("{}: {}", problem.title, problem.detail)
    };
    ErrorData::new(
        ErrorCode(code),
        detail,
        Some(serde_json::json!({
            "hint": hint,
            "error_type": error_type,
            "http_status": status,
            "problem_type": problem.problem_type,
        })),
    )
}

/// Derive (code, error_type, hint) from HTTP status and problem_type slug.
fn classify_http(status: u16, problem_type: &str) -> (i32, &'static str, &'static str) {
    match status {
        401 => (
            codes::UNSEAL_REQUIRED,
            "vault.unsealed_required",
            "Unseal the vault first",
        ),
        403 => (
            codes::ACCESS_DENIED,
            "vault.access_denied",
            "Pass operator_confirmation=true via slash command",
        ),
        404 => (
            codes::HANDLE_NOT_FOUND,
            "vault.not_found",
            "Verify the handle URI with vault.list",
        ),
        409 => (codes::CONFLICT, "vault.conflict", "Resource conflict"),
        400 => (
            codes::BAD_REQUEST,
            "vault.bad_request",
            "Check the request parameters",
        ),
        501 => (
            codes::TOOL_NOT_IMPLEMENTED,
            "vault.not_implemented",
            "This capability is planned for a future release",
        ),
        503 => (
            codes::SERVICE_UNAVAILABLE,
            "vault.service_unavailable",
            "The agent is temporarily unavailable; retry shortly",
        ),
        _ => classify_by_slug(problem_type),
    }
}

/// When the HTTP status is not a well-known code, try to map by slug.
fn classify_by_slug(slug: &str) -> (i32, &'static str, &'static str) {
    if slug.contains("reveal.denied") || slug.contains("policy") {
        return (
            codes::REVEAL_DENIED,
            "vault.reveal_denied",
            "Pass operator_confirmation=true via /merkle-reveal slash command",
        );
    }
    if slug.contains("rate_limit") || slug.contains("rate-limit") {
        return (
            codes::RATE_LIMIT_EXCEEDED,
            "vault.rate_limit",
            "Wait for the rate-limit window to expire",
        );
    }
    if slug.contains("ssh.auth") {
        return (
            codes::SSH_AUTH_FAILED,
            "vault.ssh_auth_failed",
            "Verify key material in the secret",
        );
    }
    if slug.contains("ssh") {
        return (
            codes::SSH_CONNECTION_FAILED,
            "vault.ssh_connection_failed",
            "Check network, firewall, and host address",
        );
    }
    if slug.contains("http") {
        return (
            codes::HTTP_REQUEST_FAILED,
            "vault.http_request_failed",
            "Check URL, TLS, and network",
        );
    }
    if slug.contains("spawn") {
        return (
            codes::SPAWN_FAILED,
            "vault.spawn_failed",
            "Check command path and permissions",
        );
    }
    if slug.contains("timeout") {
        return (
            codes::COMMAND_TIMEOUT,
            "vault.command_timeout",
            "Increase timeout or check for hang",
        );
    }
    if slug.contains("tempfile") {
        return (
            codes::TEMPFILE_CREATE_FAILED,
            "vault.tempfile_failed",
            "Check permissions on the temp directory",
        );
    }
    (
        codes::SERVER_ERROR,
        "vault.server_error",
        "Unexpected internal error; check agent logs",
    )
}

// ---------------------------------------------------------------------------
// Named constructor helpers used by tool implementations
// ---------------------------------------------------------------------------

/// Build an `ErrorData` for a not-yet-implemented tool (server returned 501).
pub fn not_implemented(tool_name: &str) -> ErrorData {
    ErrorData::new(
        ErrorCode(codes::TOOL_NOT_IMPLEMENTED),
        format!("Tool '{tool_name}' is scaffolded but not yet implemented"),
        Some(serde_json::json!({
            "hint": "This tool is planned for a future release.",
            "error_type": "vault.not_implemented",
        })),
    )
}

/// Build an `ErrorData` for a session `AlreadyBound` condition.
pub fn already_bound() -> ErrorData {
    ErrorData::new(
        ErrorCode(codes::ALREADY_BOUND),
        "AlreadyBound: session already bound to a Namespace",
        Some(serde_json::json!({
            "hint": "One binding per session; start a new session to change.",
            "error_type": "AlreadyBound",
        })),
    )
}

/// Build an `ErrorData` for `NamespaceNotBound`.
pub fn namespace_not_bound() -> ErrorData {
    ErrorData::new(
        ErrorCode(codes::NAMESPACE_NOT_BOUND),
        "NamespaceNotBound: session has no Namespace binding",
        Some(serde_json::json!({
            "hint": "Call vault.bind first.",
            "error_type": "NamespaceNotBound",
        })),
    )
}
