//! `PortForwardCommand` — TCP port-forward via SSH subprocess (ADR-0023).
//!
//! Spawns a long-lived `ssh -N -L local:remote_host:remote_port target` child
//! using key material on a mode-0600 tempfile. The child is registered in
//! [`AppContext::active_port_forwards`] under a session id.

use std::process::Stdio;

use crate::{AppContext, AppError};
use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;
use merkle_types::{AuditOp, AuditOutcome, NamespaceId, Sensitivity, UuidV7};
use tempfile::NamedTempFile;
use tokio::process::Command;
use tracing::{info, warn};

/// Input for `PortForwardCommand`.
#[derive(Debug)]
pub struct PortForwardCommand {
    /// Namespace to audit under.
    pub namespace_id: NamespaceId,
    /// SSH target (`user@host` or `host`).
    pub ssh_target: String,
    /// PEM-encoded SSH private key bytes.
    pub key_material: Vec<u8>,
    /// Local port to bind on `127.0.0.1`.
    pub local_port: u16,
    /// Remote host for the forwarded connection.
    pub remote_host: String,
    /// Remote port for the forwarded connection.
    pub remote_port: u16,
    /// Sensitivity of the SSH key secret being used.
    pub sensitivity: Sensitivity,
    /// Operator confirmation flags (ADR-0011).
    pub operator_confirmation: OperatorConfirmation,
}

/// Successful output of `PortForwardCommand`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PortForwardOutput {
    /// UuidV7 session identifier for this active tunnel.
    pub session_id: UuidV7,
    /// Bound local address, e.g. `"127.0.0.1:8080"`.
    pub local_addr: String,
}

impl PortForwardCommand {
    /// Execute port-forward.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault is not in Unsealed state.
    /// - [`AppError::PolicyDenied`] — missing slash command / oob for high.
    /// - [`AppError::Domain`] — ssh spawn failed.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<PortForwardOutput, AppError> {
        ctx.require_unsealed().await?;

        if !self.operator_confirmation.slash_command {
            deny_audit(ctx, self.namespace_id, "missing_slash_command").await?;
            return Err(AppError::PolicyDenied("missing_slash_command".into()));
        }
        if self.sensitivity == Sensitivity::High && !self.operator_confirmation.oob_ack {
            deny_audit(ctx, self.namespace_id, "missing_oob_ack").await?;
            return Err(AppError::PolicyDenied("missing_oob_ack".into()));
        }
        if self.local_port == 0 {
            return Err(AppError::InvalidInput("local_port must be non-zero".into()));
        }
        if self.ssh_target.trim().is_empty()
            || self.remote_host.trim().is_empty()
            || self.key_material.is_empty()
        {
            return Err(AppError::InvalidInput(
                "ssh_target, remote_host, and key_material are required".into(),
            ));
        }

        let identity_file = write_identity_0600(&self.key_material)?;
        let forward_spec = format!(
            "{}:{}:{}",
            self.local_port, self.remote_host, self.remote_port
        );
        let local_addr = format!("127.0.0.1:{}", self.local_port);

        info!(
            target = %self.ssh_target,
            forward = %forward_spec,
            "port_forward: spawning ssh -N -L"
        );

        let mut child = Command::new("ssh")
            .arg("-i")
            .arg(identity_file.path())
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("StrictHostKeyChecking=accept-new")
            .arg("-o")
            .arg("ExitOnForwardFailure=yes")
            .arg("-N")
            .arg("-L")
            .arg(&forward_spec)
            .arg("--")
            .arg(&self.ssh_target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    AppError::Domain("ssh binary not found in PATH".into())
                } else {
                    AppError::Domain(format!("failed to spawn ssh port-forward: {e}"))
                }
            })?;

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        if let Ok(Some(status)) = child.try_wait() {
            let mut err = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                use tokio::io::AsyncReadExt as _;
                let mut buf = Vec::new();
                let _ = stderr.read_to_end(&mut buf).await;
                err = String::from_utf8_lossy(&buf).into_owned();
            }
            warn!(?status, %err, "port_forward: ssh exited immediately");
            return Err(AppError::Domain(format!(
                "ssh port-forward failed to stay up: {status}; {err}"
            )));
        }

        // Persist identity path for the life of the child (NamedTempFile would
        // unlink on drop while ssh still holds -i). Clean up when child exits.
        let (_kept_file, identity_path) = identity_file
            .keep()
            .map_err(|e| AppError::Domain(format!("persist identity tempfile: {e}")))?;
        let session_id = UuidV7::new();
        {
            let mut map = ctx.active_port_forwards.write().await;
            map.insert(session_id, child);
        }

        // Detached cleanup: when session is removed or process dies, best-effort
        // unlink. We poll the map; if session gone, remove file.
        let ctx_cleanup = ctx.clone();
        let path_cleanup = identity_path;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let gone = {
                    let map = ctx_cleanup.active_port_forwards.read().await;
                    !map.contains_key(&session_id)
                };
                if gone {
                    let _ = tokio::fs::remove_file(&path_cleanup).await;
                    break;
                }
                // Also remove if child finished (caller may leave map entry).
                let finished = {
                    let mut map = ctx_cleanup.active_port_forwards.write().await;
                    if let Some(child) = map.get_mut(&session_id) {
                        matches!(child.try_wait(), Ok(Some(_)))
                    } else {
                        true
                    }
                };
                if finished {
                    let mut map = ctx_cleanup.active_port_forwards.write().await;
                    map.remove(&session_id);
                    let _ = tokio::fs::remove_file(&path_cleanup).await;
                    break;
                }
            }
        });

        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::PortForward,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(%session_id, %local_addr, "port_forward: tunnel active");
        Ok(PortForwardOutput {
            session_id,
            local_addr,
        })
    }
}

async fn deny_audit(
    ctx: &AppContext,
    namespace_id: NamespaceId,
    reason: &str,
) -> Result<(), AppError> {
    let hmac_key = ctx.require_hmac_key().await?;
    let params = merkle_domain_audit_compliance::AppendParams::new(
        AuditOp::PortForward,
        AuditOutcome::Deny,
        namespace_id,
    )
    .denial_reason(reason)
    .caller_program("merkle-agent");
    crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await
}

fn write_identity_0600(key_material: &[u8]) -> Result<NamedTempFile, AppError> {
    use std::io::Write as _;
    let mut file =
        NamedTempFile::new().map_err(|e| AppError::Domain(format!("identity tempfile: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(|e| AppError::Domain(format!("chmod identity: {e}")))?;
    }
    file.write_all(key_material)
        .map_err(|e| AppError::Domain(format!("write identity: {e}")))?;
    file.flush()
        .map_err(|e| AppError::Domain(format!("flush identity: {e}")))?;
    Ok(file)
}
