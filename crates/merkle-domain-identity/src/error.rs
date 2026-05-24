//! Domain-level error types for the Identity and Sealing bounded context.

use thiserror::Error;

use crate::sealed_state::SealedState;

/// All errors that can be returned by the IdentityAndSealing domain.
///
/// Every variant carries enough context to produce a meaningful log entry
/// without leaking key material or internal memory addresses.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DomainError {
    /// A state transition was requested that is not permitted by the
    /// sealed-state machine.
    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition {
        /// The current state of the vault identity.
        from: SealedState,
        /// The requested next state.
        to: SealedState,
    },

    /// An Argon2id parameter is below the minimum hardness floor mandated by
    /// ADR-0005.
    #[error(
        "argon2id parameter `{field}` is below the minimum floor: got {got}, minimum is {min}"
    )]
    Argon2idBelowFloor {
        /// The parameter name (`m_cost`, `t_cost`, or `p_cost`).
        field: &'static str,
        /// The supplied value.
        got: u32,
        /// The minimum permitted value.
        min: u32,
    },

    /// The VaultRootKey is already present when it must be absent, or absent
    /// when it must be present.
    #[error("vault root key invariant violated: {detail}")]
    VaultRootKeyInvariant {
        /// Human-readable description of the invariant violation.
        detail: &'static str,
    },

    /// A precondition required to begin unsealing was not satisfied.
    #[error("unseal precondition failed: {reason}")]
    UnsealPreconditionFailed {
        /// Human-readable description of the failed precondition.
        reason: &'static str,
    },

    /// The vault is in Sealed state and does not permit this operation.
    #[error("vault is sealed; operation rejected")]
    VaultSealed,

    /// The vault is already in Unsealed state; the unseal is a no-op.
    #[error("vault is already unsealed; idempotent call succeeded")]
    AlreadyUnsealed,

    /// Passphrase derivation is not implemented at the domain layer; the
    /// caller must provide a concrete crypto adapter.
    #[error("passphrase derivation requires a crypto adapter; stub only")]
    DerivationNotImplemented,
}
