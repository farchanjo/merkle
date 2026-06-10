//! `SshCopyCommand` — copy a file to/from a remote host using a vault SSH key.
//!
//! Calls [`ExternalServices::ssh_exec`] to run an `scp`-equivalent command on
//! the remote side. Audited with `op=ssh_copy`.

use merkle_types::{AuditOp, AuditOutcome, NamespaceId};
use tracing::info;

use crate::{AppContext, AppError};

/// POSIX-shell single-quote a string so it is passed as a single literal
/// argument to the remote shell.
///
/// The remote side runs `scp <source> <destination>` through a shell, so any
/// metacharacter in an unquoted path (`'`, `;`, `&&`, `$()`, …) would otherwise
/// be interpreted. Wrapping in single quotes neutralises everything; an
/// embedded `'` is escaped as `'\''` (close-quote, literal quote, re-open).
fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Input for SSH copy.
#[derive(Debug)]
pub struct SshCopyCommand {
    /// Namespace to audit under.
    pub namespace_id: NamespaceId,
    /// SSH target (`host:port`) for the connection.
    pub target: String,
    /// Source path (local or remote).
    pub source: String,
    /// Destination path (local or remote).
    pub destination: String,
    /// PEM-encoded SSH private key bytes.
    pub key_material: Vec<u8>,
}

/// Output of `SshCopyCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SshCopyOutput {
    /// Exit code returned by the remote copy command.
    pub exit_code: i32,
    /// Captured stderr bytes.
    pub stderr: Vec<u8>,
}

impl SshCopyCommand {
    /// Execute ssh-copy.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::External`] — SSH connection or command failed.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<SshCopyOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(target = %self.target, "ssh_copy: executing remote copy");

        let scp_cmd = format!(
            "scp {} {}",
            shell_single_quote(&self.source),
            shell_single_quote(&self.destination)
        );
        let result = ctx
            .external
            .ssh_exec(&self.target, &self.key_material, &scp_cmd)
            .await?;

        // Audit: op=ssh_copy.
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::SshCopy,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        let (entry, pinned) =
            merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                .map_err(|e| AppError::Domain(e.to_string()))?;
        drop(log);
        ctx.storage.append_audit_entry(&entry).await?;
        ctx.storage.update_pinned_head(&pinned).await?;

        info!(exit_code = result.exit_code, "ssh_copy: complete");
        Ok(SshCopyOutput {
            exit_code: result.exit_code,
            stderr: result.stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::shell_single_quote;

    #[test]
    fn plain_path_is_wrapped_in_single_quotes() {
        assert_eq!(shell_single_quote("/tmp/file"), "'/tmp/file'");
    }

    #[test]
    fn injection_attempt_is_neutralised() {
        // Classic break-out attempt: a single quote followed by a command.
        let malicious = "a' && id && echo '";
        let quoted = shell_single_quote(malicious);
        // Every embedded quote is escaped as '\'' so the whole thing stays a
        // single literal argument — no `&&`, no command substitution escapes.
        assert_eq!(quoted, "'a'\\'' && id && echo '\\'''");
        assert!(quoted.starts_with('\'') && quoted.ends_with('\''));
    }
}
