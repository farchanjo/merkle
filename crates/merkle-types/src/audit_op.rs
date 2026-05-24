//! `AuditOp` — closed enum of all 31 auditable vault operations.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ParseError;

/// All auditable vault operations.
///
/// This enum is **closed** (`#[non_exhaustive]` is intentionally absent) —
/// new operations require an ADR before adding a variant.
/// Total variants: 31, matching `#AuditOp` in `audit_entry.cue`.
/// Amendment 2026-05-23: added `Init` per ADR-0021.
///
/// ```
/// use merkle_types::AuditOp;
///
/// let op: AuditOp = "reveal".parse().unwrap();
/// assert_eq!(op, AuditOp::Reveal);
/// assert_eq!(op.to_string(), "reveal");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOp {
    /// Query the audit log.
    #[serde(rename = "audit_query")]
    AuditQuery,
    /// Initialize a fresh vault (bootstrap ceremony, ADR-0021).
    #[serde(rename = "init")]
    Init,
    /// Create or update a backup.
    #[serde(rename = "backup")]
    Backup,
    /// Bind a namespace to a working directory.
    #[serde(rename = "bind")]
    Bind,
    /// Create a custom category.
    #[serde(rename = "category_create")]
    CategoryCreate,
    /// Decrypt material via the crypto adapter.
    #[serde(rename = "crypto_decrypt")]
    CryptoDecrypt,
    /// Sign data via the crypto adapter.
    #[serde(rename = "crypto_sign")]
    CryptoSign,
    /// Emit a cross-environment warning.
    #[serde(rename = "cross_env_warning")]
    CrossEnvWarning,
    /// Delete a secret.
    #[serde(rename = "delete")]
    Delete,
    /// Describe a secret's public metadata.
    #[serde(rename = "describe")]
    Describe,
    /// Execute disaster recovery procedure.
    #[serde(rename = "disaster_recovery")]
    DisasterRecovery,
    /// Run the vault doctor diagnostic.
    #[serde(rename = "doctor")]
    Doctor,
    /// Get a secret (proxy/non-reveal access).
    #[serde(rename = "get")]
    Get,
    /// Download a file via HTTP bridge.
    #[serde(rename = "http_download")]
    HttpDownload,
    /// Make an HTTP request via the HTTP bridge.
    #[serde(rename = "http_request")]
    HttpRequest,
    /// Upload a file via HTTP bridge.
    #[serde(rename = "http_upload")]
    HttpUpload,
    /// List secrets in a namespace.
    #[serde(rename = "list")]
    List,
    /// Create a new namespace.
    #[serde(rename = "namespace_create")]
    NamespaceCreate,
    /// Forward a TCP port through the SSH bridge.
    #[serde(rename = "port_forward")]
    PortForward,
    /// Create or update a secret.
    #[serde(rename = "put")]
    Put,
    /// Restore a backup.
    #[serde(rename = "restore")]
    Restore,
    /// Reveal a secret's plaintext to the MCP transport.
    #[serde(rename = "reveal")]
    Reveal,
    /// Rotate a secret to a new version.
    #[serde(rename = "rotate")]
    Rotate,
    /// Search secrets by full-text or tags.
    #[serde(rename = "search")]
    Search,
    /// Spawn a process with secret environment variables.
    #[serde(rename = "spawn")]
    Spawn,
    /// Copy a file via SSH bridge.
    #[serde(rename = "ssh_copy")]
    SshCopy,
    /// Execute a remote command via SSH bridge.
    #[serde(rename = "ssh_exec")]
    SshExec,
    /// Unseal the vault (load Vault Root Key into memory).
    #[serde(rename = "unseal")]
    Unseal,
    /// Obtain a use token for proxy access.
    #[serde(rename = "use")]
    Use,
    /// Resolve a use token on the Companion Socket.
    #[serde(rename = "use_token_resolved")]
    UseTokenResolved,
    /// Write a secret to a temporary file.
    #[serde(rename = "write_tempfile")]
    WriteTempfile,
}

impl fmt::Display for AuditOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AuditQuery => "audit_query",
            Self::Init => "init",
            Self::Backup => "backup",
            Self::Bind => "bind",
            Self::CategoryCreate => "category_create",
            Self::CryptoDecrypt => "crypto_decrypt",
            Self::CryptoSign => "crypto_sign",
            Self::CrossEnvWarning => "cross_env_warning",
            Self::Delete => "delete",
            Self::Describe => "describe",
            Self::DisasterRecovery => "disaster_recovery",
            Self::Doctor => "doctor",
            Self::Get => "get",
            Self::HttpDownload => "http_download",
            Self::HttpRequest => "http_request",
            Self::HttpUpload => "http_upload",
            Self::List => "list",
            Self::NamespaceCreate => "namespace_create",
            Self::PortForward => "port_forward",
            Self::Put => "put",
            Self::Restore => "restore",
            Self::Reveal => "reveal",
            Self::Rotate => "rotate",
            Self::Search => "search",
            Self::Spawn => "spawn",
            Self::SshCopy => "ssh_copy",
            Self::SshExec => "ssh_exec",
            Self::Unseal => "unseal",
            Self::Use => "use",
            Self::UseTokenResolved => "use_token_resolved",
            Self::WriteTempfile => "write_tempfile",
        };
        f.write_str(s)
    }
}

impl FromStr for AuditOp {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "audit_query" => Ok(Self::AuditQuery),
            "init" => Ok(Self::Init),
            "backup" => Ok(Self::Backup),
            "bind" => Ok(Self::Bind),
            "category_create" => Ok(Self::CategoryCreate),
            "crypto_decrypt" => Ok(Self::CryptoDecrypt),
            "crypto_sign" => Ok(Self::CryptoSign),
            "cross_env_warning" => Ok(Self::CrossEnvWarning),
            "delete" => Ok(Self::Delete),
            "describe" => Ok(Self::Describe),
            "disaster_recovery" => Ok(Self::DisasterRecovery),
            "doctor" => Ok(Self::Doctor),
            "get" => Ok(Self::Get),
            "http_download" => Ok(Self::HttpDownload),
            "http_request" => Ok(Self::HttpRequest),
            "http_upload" => Ok(Self::HttpUpload),
            "list" => Ok(Self::List),
            "namespace_create" => Ok(Self::NamespaceCreate),
            "port_forward" => Ok(Self::PortForward),
            "put" => Ok(Self::Put),
            "restore" => Ok(Self::Restore),
            "reveal" => Ok(Self::Reveal),
            "rotate" => Ok(Self::Rotate),
            "search" => Ok(Self::Search),
            "spawn" => Ok(Self::Spawn),
            "ssh_copy" => Ok(Self::SshCopy),
            "ssh_exec" => Ok(Self::SshExec),
            "unseal" => Ok(Self::Unseal),
            "use" => Ok(Self::Use),
            "use_token_resolved" => Ok(Self::UseTokenResolved),
            "write_tempfile" => Ok(Self::WriteTempfile),
            other => Err(ParseError::UnknownAuditOp(other.to_owned())),
        }
    }
}

impl TryFrom<&str> for AuditOp {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for AuditOp {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_OPS: &[(&str, AuditOp)] = &[
        ("audit_query", AuditOp::AuditQuery),
        ("init", AuditOp::Init),
        ("backup", AuditOp::Backup),
        ("bind", AuditOp::Bind),
        ("category_create", AuditOp::CategoryCreate),
        ("crypto_decrypt", AuditOp::CryptoDecrypt),
        ("crypto_sign", AuditOp::CryptoSign),
        ("cross_env_warning", AuditOp::CrossEnvWarning),
        ("delete", AuditOp::Delete),
        ("describe", AuditOp::Describe),
        ("disaster_recovery", AuditOp::DisasterRecovery),
        ("doctor", AuditOp::Doctor),
        ("get", AuditOp::Get),
        ("http_download", AuditOp::HttpDownload),
        ("http_request", AuditOp::HttpRequest),
        ("http_upload", AuditOp::HttpUpload),
        ("list", AuditOp::List),
        ("namespace_create", AuditOp::NamespaceCreate),
        ("port_forward", AuditOp::PortForward),
        ("put", AuditOp::Put),
        ("restore", AuditOp::Restore),
        ("reveal", AuditOp::Reveal),
        ("rotate", AuditOp::Rotate),
        ("search", AuditOp::Search),
        ("spawn", AuditOp::Spawn),
        ("ssh_copy", AuditOp::SshCopy),
        ("ssh_exec", AuditOp::SshExec),
        ("unseal", AuditOp::Unseal),
        ("use", AuditOp::Use),
        ("use_token_resolved", AuditOp::UseTokenResolved),
        ("write_tempfile", AuditOp::WriteTempfile),
    ];

    #[test]
    fn exactly_31_variants() {
        assert_eq!(ALL_OPS.len(), 31, "AuditOp must have exactly 31 variants");
    }

    #[test]
    fn all_variants_round_trip() {
        for (s, expected) in ALL_OPS {
            let parsed: AuditOp = s.parse().unwrap_or_else(|_| panic!("failed to parse: {s}"));
            assert_eq!(&parsed, expected, "parse mismatch for {s}");
            assert_eq!(parsed.to_string(), *s, "display mismatch for {s}");
        }
    }

    #[test]
    fn rejects_unknown() {
        assert!("unknown_op".parse::<AuditOp>().is_err());
    }

    #[test]
    fn serde_json_round_trip() {
        for (_, op) in ALL_OPS {
            let json = serde_json::to_string(op).unwrap();
            let parsed: AuditOp = serde_json::from_str(&json).unwrap();
            assert_eq!(op, &parsed);
        }
    }
}
