//! `AgentStatusQuery` — aggregate sealed state and OOB availability.

use merkle_domain_identity::SealedState;
use tracing::info;

use crate::{AppContext, AppError};

/// Input for agent status (unit-struct; no parameters required).
#[derive(Debug, Default)]
pub struct AgentStatusQuery;

/// Output of `AgentStatusQuery`.
#[derive(Debug)]
pub struct AgentStatusOutput {
    /// Current sealed/unsealed state of the vault.
    pub sealed_state: SealedState,

    /// Whether the OOB notifier channel is currently reachable.
    pub oob_available: bool,
}

impl AgentStatusQuery {
    /// Execute agent-status.
    ///
    /// This is one of the few queries that does NOT require the vault to be
    /// Unsealed — status is useful precisely when the vault is Sealed.
    ///
    /// # Errors
    ///
    /// Currently infallible; returns `Ok` in all cases.
    pub async fn execute(&self, ctx: &AppContext) -> Result<AgentStatusOutput, AppError> {
        info!("agent_status: collecting status");

        let sealed_state = ctx.identity.read().await.state();
        let oob_available = ctx.oob.available().await;

        Ok(AgentStatusOutput {
            sealed_state,
            oob_available,
        })
    }
}
