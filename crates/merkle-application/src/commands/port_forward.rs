//! `PortForwardCommand` — TCP port-forward via SSH subprocess (ADR-0023).
//!
//! Spawns a long-lived `ssh -L <local_port>:<remote_host>:<remote_port>
//! <ssh_target>` child process using key material written to a `mode 0600`
//! tempfile. Returns a [`UuidV7`] session id so the caller can later
//! terminate the tunnel.
//!
//! # Policy gate
//!
//! When `sensitivity = high` the slash-command confirmation flag from
//! ADR-0011 MUST be present. Missing it produces `outcome = Deny` in the
//! audit log without spawning any process.
//!
//! # Audit
//!
//! - Success: `op = PortForward, outcome = Allow`.
//! - Policy denial: `op = PortForward, outcome = Deny,
//!   denial_reason = "missing_slash_command"`.

use std::os::unix::fs::PermissionsExt as _;

use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;
use merkle_types::{AuditOp, AuditOutcome, NamespaceId, Sensitivity, UuidV7};
use tokio::fs;
use tokio::process::Command;
use tracing::info;

use crate::{AppContext, AppError};

/// Input for `PortForwardCommand`.
#[derive(Debug)]
pub struct PortForwardCommand {
    /// Namespace to audit under.
    pub namespace_id: NamespaceId,
    /// SSH target in `host:port` form (e.g. `"bastion.example.com:22"`).
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
    ///
    /// Pass to `RevokePortForwardCommand` (Phase 7+) to terminate the
    /// underlying `ssh` subprocess.
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
    /// - [`AppError::PolicyDenied`] — `sensitivity=high` key without slash-command
    ///   confirmation.
    /// - [`AppError::Domain`] — tempfile write failed or `ssh` subprocess failed
    ///   to start.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<PortForwardOutput, AppError> {
        ctx.require_unsealed().await?;

        // ------------------------------------------------------------------
        // Policy gate: sensitivity=high requires slash-command confirmation.
        // ------------------------------------------------------------------
        if self.sensitivity == Sensitivity::High && !self.operator_confirmation.slash_confirmed() {
            info!(
                target = %self.ssh_target,
                "port_forward: denied — sensitivity=high requires slash_command confirmation"
            );

            let hmac_key = ctx.require_hmac_key().await?;
            let mut log = ctx.audit_log.write().await;
            let params = merkle_domain_audit_compliance::AppendParams::new(
                AuditOp::PortForward,
                AuditOutcome::Deny,
                self.namespace_id,
            )
            .denial_reason("missing_slash_command")
            .caller_program("merkle-agent");
            let (entry, pinned) =
                merkle_domain_audit_compliance::AuditWriter::append(&mut log, params, &hmac_key)
                    .map_err(|e| AppError::Domain(e.to_string()))?;
            drop(log);
            ctx.storage.append_audit_entry(&entry).await?;
            ctx.storage.update_pinned_head(&pinned).await?;

            return Err(AppError::PolicyDenied(
                "missing_slash_command".into(),
            ));
        }

        // ------------------------------------------------------------------
        // Write key material to a mode-0600 tempfile.
        // ------------------------------------------------------------------
        let session_id = UuidV7::new();
        let tmp_path = std::env::temp_dir().join(format!("merkle-pf-{session_id}.key"));

        fs::write(&tmp_path, &self.key_material)
            .await
            .map_err(|e| AppError::Domain(format!("port_forward: write key tempfile: {e}")))?;

        // Restrict permissions to owner-read-write only.
        let perms = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(&tmp_path, perms)
            .await
            .map_err(|e| AppError::Domain(format!("port_forward: set tempfile perms: {e}")))?;

        // ------------------------------------------------------------------
        // Spawn the `ssh -L` child process (non-awaited background tunnel).
        // ------------------------------------------------------------------
        let forward_spec = format!(
            "{}:{}:{}",
            self.local_port, self.remote_host, self.remote_port,
        );

        info!(
            target = %self.ssh_target,
            forward = %forward_spec,
            session_id = %session_id,
            "port_forward: spawning ssh -L tunnel"
        );

        let child = Command::new("ssh")
            .args([
                "-i",
                tmp_path
                    .to_str()
                    .ok_or_else(|| AppError::Domain("port_forward: non-UTF8 tmpdir".into()))?,
                "-N",
                "-L",
                &forward_spec,
                &self.ssh_target,
            ])
            // Suppress terminal I/O.
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| AppError::Domain(format!("port_forward: ssh spawn failed: {e}")))?;

        // Register the child in the active-tunnel registry for later revocation.
        {
            let mut tunnels = ctx.active_port_forwards.write().await;
            tunnels.insert(session_id, child);
        }

        // ------------------------------------------------------------------
        // Audit: op=PortForward, outcome=Allow.
        // ------------------------------------------------------------------
        let hmac_key = ctx.require_hmac_key().await?;
        let mut log = ctx.audit_log.write().await;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::PortForward,
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

        let local_addr = format!("127.0.0.1:{}", self.local_port);
        info!(
            session_id = %session_id,
            local_addr = %local_addr,
            "port_forward: tunnel active"
        );

        Ok(PortForwardOutput {
            session_id,
            local_addr,
        })
    }
}
