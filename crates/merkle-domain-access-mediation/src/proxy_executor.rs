//! `ProxyExecutor` — value object describing a proxy tool configuration.

use merkle_types::CategoryName;
use serde::{Deserialize, Serialize};

/// The set of operations the `ProxyExecutor` domain service is authorized to
/// perform.  The enum is closed; adding an operation requires an ADR and a
/// schema update.
///
/// Mirrors `#ProxyOperation` in `proxy_executor.cue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyToolName {
    /// `vault.ssh.exec` — execute a command over an SSH connection.
    SshExec,
    /// `vault.ssh.copy` — copy a file over SCP/SFTP.
    SshCopy,
    /// `vault.ssh.shell` — drive an interactive SSH shell.
    SshShell,
    /// `vault.ssh.port_forward` — establish an SSH port forward.
    SshPortForward,
    /// `vault.http.request` — perform an authenticated HTTP request.
    HttpRequest,
    /// `vault.http.download` — download a file via HTTP with credential injection.
    HttpDownload,
    /// `vault.http.upload` — upload a file via HTTP with credential injection.
    HttpUpload,
    /// `vault.spawn` — spawn a child process with selected env-vars from the Secret.
    Spawn,
    /// `vault.write_tempfile` — materialize the Secret to a tempfile or FIFO.
    WriteTempfile,
    /// `vault.crypto.sign` — produce a signature using a key Secret.
    CryptoSign,
    /// `vault.crypto.decrypt` — decrypt a ciphertext using a key Secret.
    CryptoDecrypt,
}

/// A `ProxyExecutor` value object that describes which proxy tool will be
/// invoked and what category constraints apply.
///
/// The `category_constraint` field lists the Secret categories that the tool
/// is permitted to operate on.  For example, `SshExec` typically requires a
/// `ssh-key` category Secret; `HttpRequest` requires a `token` or `password`
/// category Secret.  An empty `category_constraint` means "any category".
///
/// ```
/// use merkle_types::CategoryName;
/// use merkle_domain_access_mediation::proxy_executor::{ProxyExecutor, ProxyToolName};
///
/// let executor = ProxyExecutor {
///     tool_name: ProxyToolName::SshExec,
///     category_constraint: vec!["ssh-key".parse::<CategoryName>().unwrap()],
/// };
/// assert_eq!(executor.tool_name, ProxyToolName::SshExec);
/// assert_eq!(executor.category_constraint.len(), 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyExecutor {
    /// Which proxy tool will be invoked.
    pub tool_name: ProxyToolName,
    /// Secret category names this tool is permitted to operate on.
    /// An empty vec means "any category is acceptable".
    pub category_constraint: Vec<CategoryName>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_types::CategoryName;

    #[test]
    fn ssh_exec_with_category_constraint() {
        let e = ProxyExecutor {
            tool_name: ProxyToolName::SshExec,
            category_constraint: vec!["ssh-key".parse::<CategoryName>().expect("parse")],
        };
        assert_eq!(e.tool_name, ProxyToolName::SshExec);
        assert_eq!(e.category_constraint.len(), 1);
    }

    #[test]
    fn serde_json_round_trip_all_tools() {
        let tools = [
            ProxyToolName::SshExec,
            ProxyToolName::SshCopy,
            ProxyToolName::SshShell,
            ProxyToolName::SshPortForward,
            ProxyToolName::HttpRequest,
            ProxyToolName::HttpDownload,
            ProxyToolName::HttpUpload,
            ProxyToolName::Spawn,
            ProxyToolName::WriteTempfile,
            ProxyToolName::CryptoSign,
            ProxyToolName::CryptoDecrypt,
        ];
        for tool in tools {
            let e = ProxyExecutor {
                tool_name: tool,
                category_constraint: vec![],
            };
            let json = serde_json::to_string(&e).expect("serialize");
            let back: ProxyExecutor = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(e.tool_name, back.tool_name);
        }
    }
}
