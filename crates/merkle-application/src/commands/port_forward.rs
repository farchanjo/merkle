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

use crate::{AppContext, AppError};
use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;
use merkle_types::{AuditOp, AuditOutcome, NamespaceId, Sensitivity, UuidV7};

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
    /// - [`AppError::PolicyDenied`] — the capability is disabled pending
    ///   confirmation and cleanup controls.
    /// - [`AppError::Storage`] — audit write failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<PortForwardOutput, AppError> {
        ctx.require_unsealed().await?;
        // Do not create a key file or an SSH child before this capability has
        // a non-forgeable confirmation path and transactional cleanup. The
        // socket adapter maps this same condition to HTTP 501.
        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::PortForward,
            AuditOutcome::Deny,
            self.namespace_id,
        )
        .denial_reason("capability_disabled_pending_security_controls")
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;
        Err(AppError::PolicyDenied(
            "port_forward_capability_disabled_pending_security_controls".into(),
        ))
    }
}
