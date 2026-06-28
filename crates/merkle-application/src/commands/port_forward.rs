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

use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;
use merkle_types::{AuditOp, AuditOutcome, NamespaceId, Sensitivity, UuidV7};
use tokio::fs;
use tokio::io::AsyncWriteExt as _;
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
            let params = merkle_domain_audit_compliance::AppendParams::new(
                AuditOp::PortForward,
                AuditOutcome::Deny,
                self.namespace_id,
            )
            .denial_reason("missing_slash_command")
            .caller_program("merkle-agent");
            crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

            return Err(AppError::PolicyDenied("missing_slash_command".into()));
        }

        // ------------------------------------------------------------------
        // Write key material to a mode-0600 tempfile.
        // ------------------------------------------------------------------
        let session_id = UuidV7::new();
        let tmp_path = std::env::temp_dir().join(format!("merkle-pf-{session_id}.key"));

        // Create the key file with 0600 atomically: `create_new` refuses to
        // follow a pre-existing path (symlink-swap defence) and `mode(0o600)`
        // applies the permission at open(2), eliminating the world-readable
        // window of a write-then-chmod sequence.
        let mut key_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .await
            .map_err(|e| AppError::Domain(format!("port_forward: create key tempfile: {e}")))?;
        key_file
            .write_all(&self.key_material)
            .await
            .map_err(|e| AppError::Domain(format!("port_forward: write key tempfile: {e}")))?;
        key_file
            .sync_all()
            .await
            .map_err(|e| AppError::Domain(format!("port_forward: sync key tempfile: {e}")))?;
        drop(key_file);

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
            // The ssh child must never inherit the keystore passphrase.
            .env_remove("MERKLE_KEYSTORE_PASSPHRASE")
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
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::PortForward,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

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
