//! Domain errors for the Access Mediation bounded context.

use merkle_types::ChallengeId;
use thiserror::Error;

/// All errors that can arise within the Access Mediation domain.
///
/// The set is closed; adapters translate infrastructure faults into one of
/// these variants before returning to the domain layer.
#[derive(Debug, Error)]
pub enum DomainError {
    /// A state transition was attempted from an invalid starting state.
    ///
    /// The first string is the current state; the second is the operation name.
    #[error("invalid state transition: cannot '{1}' when in state '{0}'")]
    InvalidStateTransition(String, &'static str),

    /// A [`crate::oob::challenge::OobChallenge`] correlated to this resolution
    /// was not found, or the `challenge_id` did not match the request's challenge.
    #[error("challenge id mismatch: expected {expected}, got {got}")]
    ChallengeMismatch {
        /// The challenge id recorded on the `RevealRequest`.
        expected: ChallengeId,
        /// The challenge id received in the `OobResolution`.
        got: ChallengeId,
    },

    /// Attempted to consume an already-consumed `UseToken`.
    #[error("use-token already consumed")]
    TokenAlreadyConsumed,

    /// The `UseToken` TTL has elapsed.
    #[error("use-token expired")]
    TokenExpired,

    /// A namespace binding was attempted on a session that already has one.
    #[error("companion socket session namespace already bound")]
    NamespaceAlreadyBound,

    /// A `RevealAuthorization` evaluation determined that authorization is
    /// denied, for the given denial reason.
    #[error("reveal denied: {reason}")]
    RevealDenied {
        /// Human-readable explanation surfaced to the LLM transport.
        reason: &'static str,
    },

    /// An invariant of the `OobResolution` value object was violated.
    ///
    /// Specifically: `outcome == Expired` with a non-None `device_signature`.
    #[error("oob resolution invariant violated: expired outcome must not carry a device_signature")]
    OobResolutionInvariantViolated,

    /// The `reason` field on a `RevealRequest` was empty.
    #[error("reveal request reason must not be empty")]
    EmptyReason,
}
