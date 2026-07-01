//! `SetAuditBaselineCommand` — pin a trusted audit baseline (ADR-0029).
//!
//! Re-anchors chain verification after a key-provenance incident. It appends a
//! [`AuditOp::Rebaseline`] marker entry under the **current** audit HMAC key,
//! then pins an authenticated [`AuditBaseline`] at that marker. From then on
//! [`crate::queries::verify_chain::VerifyChainQuery`] verifies structural
//! integrity across the whole log but authenticates entry HMACs only from the
//! marker forward; the operator-attested prefix is quarantined.
//!
//! Anchoring on the freshly-written marker (rather than an arbitrary historical
//! seq) guarantees the anchor entry is authentic under the current key,
//! regardless of any historical VRK/keystore divergence.
//!
//! Operator-gated: this is an integrity-affecting administrative action, so it
//! requires explicit operator confirmation and is deliberately NOT exposed as an
//! MCP tool (MERK-001) — only the operator CLI and Companion Socket reach it.

use merkle_domain_audit_compliance::{AppendParams, AuditBaseline};
use merkle_types::{AuditOp, AuditOutcome, NamespaceId, Rfc3339Timestamp};
use tracing::info;

use crate::{AppContext, AppError};

/// Input for pinning a trusted audit baseline.
#[derive(Debug, Clone)]
pub struct SetAuditBaselineCommand {
    /// Operator-provided justification, recorded with the baseline.
    pub reason: String,
    /// Must be `true`: explicit operator confirmation for this integrity op.
    pub confirmed: bool,
}

/// Output of a successful [`SetAuditBaselineCommand`].
#[derive(Debug)]
pub struct SetAuditBaselineOutput {
    /// Sequence number of the pinned anchor (the marker entry).
    pub baseline_seq: u64,
    /// Number of prior entries now quarantined below the baseline.
    pub quarantined_below: u64,
}

impl SetAuditBaselineCommand {
    /// Execute the re-baseline.
    ///
    /// # Errors
    ///
    /// - [`AppError::Domain`] — confirmation missing, or no pinned head exists
    ///   after the marker append (uninitialized vault).
    /// - [`AppError::VaultSealed`] — the vault is not Unsealed.
    /// - [`AppError::Storage`] — audit or baseline persistence failed.
    pub async fn execute(&self, ctx: &AppContext) -> Result<SetAuditBaselineOutput, AppError> {
        if !self.confirmed {
            return Err(AppError::Domain(
                "re-baseline requires explicit operator confirmation".into(),
            ));
        }
        ctx.require_unsealed().await?;
        let key = ctx.require_hmac_key().await?;

        info!("set_audit_baseline: appending rebaseline marker entry");

        // Append the Rebaseline marker under the CURRENT key. Anchoring on this
        // fresh, authentic entry makes the baseline valid regardless of any
        // historical key-provenance divergence in the quarantined prefix.
        let params =
            AppendParams::new(AuditOp::Rebaseline, AuditOutcome::Allow, NamespaceId::new())
                .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &key).await?;

        // The pinned head now points at the marker we just wrote.
        let head = ctx.storage.pinned_head().await?.ok_or_else(|| {
            AppError::Domain("no pinned head after rebaseline marker append".into())
        })?;

        let entry_count = head.head_seq.saturating_add(1);
        let baseline = AuditBaseline::new(
            head.head_seq,
            head.head_id,
            head.head_hash,
            entry_count,
            self.reason.clone(),
            Rfc3339Timestamp::now(),
        )
        .with_mac(&key);

        ctx.storage.set_audit_baseline(&baseline).await?;

        info!(
            baseline_seq = head.head_seq,
            quarantined_below = head.head_seq,
            "set_audit_baseline: trusted baseline pinned"
        );
        Ok(SetAuditBaselineOutput {
            baseline_seq: head.head_seq,
            quarantined_below: head.head_seq,
        })
    }
}
