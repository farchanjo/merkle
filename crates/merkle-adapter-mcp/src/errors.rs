//! MCP error mapping.
//!
//! Maps `AppError` and `anyhow::Error` values to structured `rmcp::ErrorData`
//! instances with the numeric codes defined in `mcp-protocol.md` Section 4.

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
    /// Tool is scaffolded but not yet implemented.
    pub const TOOL_NOT_IMPLEMENTED: i32 = -32099;
}

/// Convert an `anyhow::Error` into an `rmcp::ErrorData`.
///
/// Inspects the error display string for symbolic names from the
/// `mcp-protocol.md` Section 4 table and maps them to the corresponding
/// numeric code. Falls back to `-32603` (Internal error) for any
/// unrecognised error.
pub fn into_mcp_error(err: &anyhow::Error) -> ErrorData {
    let msg = err.to_string();
    let (code, hint, error_type) = classify(&msg);
    ErrorData::new(
        ErrorCode(code),
        std::borrow::Cow::Owned(msg),
        Some(serde_json::json!({
            "hint": hint,
            "error_type": error_type,
        })),
    )
}

/// Convert a `merkle_application::AppError` into an `rmcp::ErrorData`.
///
/// Takes ownership so callers can use it as `map_err(app_error_to_mcp)` directly.
#[expect(clippy::needless_pass_by_value, reason = "map_err needs ownership; taking &AppError would require a closure wrapper at every call site")]
pub fn app_error_to_mcp(err: merkle_application::AppError) -> ErrorData {
    let msg = err.to_string();
    let (code, hint, error_type) = classify(&msg);
    ErrorData::new(
        ErrorCode(code),
        std::borrow::Cow::Owned(msg),
        Some(serde_json::json!({
            "hint": hint,
            "error_type": error_type,
        })),
    )
}

/// Build an `ErrorData` for a not-yet-implemented tool.
pub fn not_implemented(tool_name: &str) -> ErrorData {
    ErrorData::new(
        ErrorCode(codes::TOOL_NOT_IMPLEMENTED),
        format!("Tool '{tool_name}' is scaffolded but not yet implemented"),
        Some(serde_json::json!({
            "hint": "This tool is planned for a future release.",
            "error_type": "ToolNotImplemented",
        })),
    )
}

/// Build an `ErrorData` for a session AlreadyBound condition.
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

/// Build an `ErrorData` for NamespaceNotBound.
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

/// Classify an error message string into (code, hint, error_type) triple.
fn classify(msg: &str) -> (i32, &'static str, &'static str) {
    if msg.contains("VaultSealed") || msg.contains("vault sealed") || msg.contains("UnsealRequired") {
        (codes::UNSEAL_REQUIRED, "Run `merkle unseal` or configure Touch ID", "UnsealRequired")
    } else if msg.contains("RateLimitExceeded") {
        (codes::RATE_LIMIT_EXCEEDED, "Wait for the rate-limit window to expire", "RateLimitExceeded")
    } else if msg.contains("RevealDenied") || msg.contains("policy denied") {
        (codes::REVEAL_DENIED, "Pass operator_confirmation: true via /merkle-reveal slash command", "RevealDenied")
    } else if msg.contains("HandleNotFound") || msg.contains("not found") {
        (codes::HANDLE_NOT_FOUND, "Verify handle URI; check vault.list", "HandleNotFound")
    } else if msg.contains("NamespaceNotBound") {
        (codes::NAMESPACE_NOT_BOUND, "Call vault.bind first", "NamespaceNotBound")
    } else if msg.contains("OobConfirmationRequired") {
        (codes::OOB_CONFIRMATION_REQUIRED, "Acknowledge the desktop notification or terminal prompt", "OobConfirmationRequired")
    } else if msg.contains("OobConfirmationTimeout") || msg.contains("oob resolution denied or expired") {
        (codes::OOB_CONFIRMATION_TIMEOUT, "Re-issue the tool call and confirm promptly", "OobConfirmationTimeout")
    } else if msg.contains("AlreadyBound") {
        (codes::ALREADY_BOUND, "One binding per session; start a new session to change", "AlreadyBound")
    } else if msg.contains("SchemaValidationFailed") || msg.contains("invalid input") {
        (codes::SCHEMA_VALIDATION_FAILED, "Check the data.fields array for constraint failures", "SchemaValidationFailed")
    } else if msg.contains("DuplicateName") {
        (codes::DUPLICATE_NAME, "Use vault.rotate to update an existing Secret", "DuplicateName")
    } else if msg.contains("SshAuthFailed") || msg.contains("ssh auth") {
        (codes::SSH_AUTH_FAILED, "Verify key material or passphrase in the Secret", "SshAuthFailed")
    } else if msg.contains("SshConnectionFailed") || msg.contains("ssh connection") {
        (codes::SSH_CONNECTION_FAILED, "Check network, firewall, and host address", "SshConnectionFailed")
    } else if msg.contains("HttpRequestFailed") || msg.contains("http request") {
        (codes::HTTP_REQUEST_FAILED, "Check URL, TLS, and network", "HttpRequestFailed")
    } else if msg.contains("SpawnFailed") || msg.contains("spawn") {
        (codes::SPAWN_FAILED, "Check command path and permissions", "SpawnFailed")
    } else if msg.contains("CommandTimeout") || msg.contains("timeout") {
        (codes::COMMAND_TIMEOUT, "Increase timeout or check for hang", "CommandTimeout")
    } else if msg.contains("TempfileCreateFailed") || msg.contains("tempfile") {
        (codes::TEMPFILE_CREATE_FAILED, "Check permissions on the temp directory", "TempfileCreateFailed")
    } else if msg.contains("not implemented") || msg.contains("NotImplemented") {
        (codes::TOOL_NOT_IMPLEMENTED, "This tool is planned for a future release", "ToolNotImplemented")
    } else {
        (-32_603, "Unexpected internal error; check agent logs", "InternalError")
    }
}
