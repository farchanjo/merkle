//! `RevealRequest` — AggregateRoot for the authorized Reveal flow.

use merkle_types::{Handle, Rfc3339Timestamp, UuidV7};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::oob::challenge::OobChallenge;
use crate::oob::resolution::OobResolution;
use crate::operator_confirmation::OperatorConfirmation;
use crate::reveal_authorization::RevealAuthorization;

/// Lifecycle states of a `RevealRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevealState {
    /// Initial state: Operator Confirmation received but not yet evaluated.
    Pending,
    /// An `OobChallenge` has been issued; waiting for the Companion Device.
    AwaitingOob,
    /// Both confirmation flags satisfied; plaintext may be loaded.
    Approved,
    /// The request was denied (missing flags, OOB timeout, policy block).
    Denied,
    /// TTL elapsed before the request was resolved.
    Expired,
    /// An unexpected error occurred during processing.
    Error,
}

/// The authorized-Reveal aggregate root.
///
/// Encapsulates the lifecycle of a `vault.reveal` call from `Pending` through
/// `Approved` or `Denied`.  The `plaintext` (not stored here — the adapter
/// layer holds it) is loaded only after the aggregate reaches `Approved`.
///
/// ## State machine
///
/// ```text
/// Pending → AwaitingOob  (via issue_challenge)
/// Pending → Approved     (via resolve, when no OOB required)
/// Pending → Denied       (via resolve, when slash_command missing)
/// AwaitingOob → Approved (via resolve, when oob_ack=true & class ok)
/// AwaitingOob → Denied   (via resolve, when OOB denied / timed out)
/// * → Expired            (via expire)
/// ```
///
/// ```
/// use merkle_types::{Handle, Rfc3339Timestamp, UuidV7};
/// use merkle_domain_access_mediation::reveal_request::{RevealRequest, RevealState};
/// use merkle_domain_access_mediation::operator_confirmation::OperatorConfirmation;
///
/// let req = RevealRequest {
///     id: UuidV7::new(),
///     session_id: UuidV7::new(),
///     handle: "vault://prod/ssh-key/bastion".parse::<Handle>().unwrap(),
///     reason: "deploy".into(),
///     operator_confirmation: OperatorConfirmation {
///         slash_command: true,
///         oob_ack: false,
///         signed_config_flag: None,
///     },
///     created_at: Rfc3339Timestamp::now(),
///     state: RevealState::Pending,
///     challenge: None,
///     resolution: None,
/// };
/// assert_eq!(req.state, RevealState::Pending);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealRequest {
    /// UUIDv7 primary key; immutable after creation.
    pub id: UuidV7,
    /// The `CompanionSocketSession` that initiated this request.
    pub session_id: UuidV7,
    /// The Secret being revealed.
    pub handle: Handle,
    /// Caller-supplied justification (minimum length 1).
    pub reason: String,
    /// Two-flag Operator Confirmation state.
    pub operator_confirmation: OperatorConfirmation,
    /// RFC 3339 timestamp when the request was created.
    pub created_at: Rfc3339Timestamp,
    /// Current lifecycle state.
    pub state: RevealState,
    /// The OOB challenge issued for this request, if any.
    pub challenge: Option<OobChallenge>,
    /// The OOB resolution received, if any.
    pub resolution: Option<OobResolution>,
}

impl RevealRequest {
    /// Issue an OOB challenge, transitioning `Pending → AwaitingOob`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidStateTransition`] when the aggregate is
    /// not in the `Pending` state.
    pub fn issue_challenge(&mut self, challenge: OobChallenge) -> Result<(), DomainError> {
        if self.state != RevealState::Pending {
            return Err(DomainError::InvalidStateTransition(
                format!("{:?}", self.state),
                "issue_challenge",
            ));
        }
        self.challenge = Some(challenge);
        self.state = RevealState::AwaitingOob;
        Ok(())
    }

    /// Resolve the request with an `OobResolution`.
    ///
    /// Validates that the resolution's `challenge_id` matches the issued
    /// challenge.  Transitions the aggregate to `Approved` or `Denied` based
    /// on the resolution outcome.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidStateTransition`] — not `Pending` or `AwaitingOob`.
    /// - [`DomainError::ChallengeMismatch`] — resolution `challenge_id` does
    ///   not match the issued challenge.
    pub fn resolve(
        &mut self,
        resolution: OobResolution,
        authorization: RevealAuthorization,
    ) -> Result<RevealAuthorization, DomainError> {
        if !matches!(self.state, RevealState::Pending | RevealState::AwaitingOob) {
            return Err(DomainError::InvalidStateTransition(
                format!("{:?}", self.state),
                "resolve",
            ));
        }

        // Validate challenge_id correlation when a challenge was issued.
        if let Some(ch) = &self.challenge {
            if ch.challenge_id != resolution.challenge_id {
                return Err(DomainError::ChallengeMismatch {
                    expected: ch.challenge_id,
                    got: resolution.challenge_id,
                });
            }
        }

        self.state = if authorization.is_allowed() {
            RevealState::Approved
        } else {
            RevealState::Denied
        };
        self.resolution = Some(resolution);
        Ok(authorization)
    }

    /// Expire the request, transitioning to `Expired`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidStateTransition`] when the aggregate is
    /// already in a terminal state (`Approved`, `Denied`, `Expired`, `Error`).
    pub fn expire(&mut self) -> Result<(), DomainError> {
        if matches!(
            self.state,
            RevealState::Approved | RevealState::Denied | RevealState::Expired | RevealState::Error
        ) {
            return Err(DomainError::InvalidStateTransition(
                format!("{:?}", self.state),
                "expire",
            ));
        }
        self.state = RevealState::Expired;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_types::{
        ChallengeId, DenialReason, Handle, NamespaceId, OobChallengeOutcome, OobChannel,
        Rfc3339Timestamp, Sensitivity, UuidV7,
    };

    fn make_request() -> RevealRequest {
        RevealRequest {
            id: UuidV7::new(),
            session_id: UuidV7::new(),
            handle: "vault://prod/ssh-key/bastion"
                .parse::<Handle>()
                .expect("parse handle"),
            reason: "deploy automation".into(),
            operator_confirmation: OperatorConfirmation {
                slash_command: true,
                oob_ack: false,
                signed_config_flag: None,
            },
            created_at: Rfc3339Timestamp::now(),
            state: RevealState::Pending,
            challenge: None,
            resolution: None,
        }
    }

    fn make_challenge(cid: &str) -> OobChallenge {
        OobChallenge {
            challenge_id: cid.parse::<ChallengeId>().expect("parse cid"),
            namespace_id: "018f4c1a-0000-7000-8000-000000000001"
                .parse::<NamespaceId>()
                .expect("parse ns_id"),
            secret_handle: "vault://prod/ssh-key/bastion"
                .parse::<Handle>()
                .expect("parse handle"),
            sensitivity: Sensitivity::High,
            oob_channel: OobChannel::DesktopNotif,
            expires_at: Rfc3339Timestamp::now(),
            request_nonce: [0u8; 32],
            envelope: None,
        }
    }

    fn make_resolution(cid: &str, outcome: OobChallengeOutcome) -> OobResolution {
        OobResolution::new(
            cid.parse::<ChallengeId>().expect("parse cid"),
            outcome,
            if outcome == OobChallengeOutcome::Approved {
                Some(Rfc3339Timestamp::now())
            } else {
                None
            },
            None,
        )
        .expect("valid resolution")
    }

    #[test]
    fn issue_challenge_from_pending_succeeds() {
        let mut r = make_request();
        r.issue_challenge(make_challenge("018f4c1a-0000-7000-8000-000000000010"))
            .expect("issue_challenge");
        assert_eq!(r.state, RevealState::AwaitingOob);
        assert!(r.challenge.is_some());
    }

    #[test]
    fn issue_challenge_from_awaiting_oob_fails() {
        let mut r = make_request();
        r.issue_challenge(make_challenge("018f4c1a-0000-7000-8000-000000000010"))
            .expect("first challenge");
        let err = r
            .issue_challenge(make_challenge("018f4c1a-0000-7000-8000-000000000011"))
            .expect_err("second challenge");
        assert!(matches!(
            err,
            DomainError::InvalidStateTransition(_, "issue_challenge")
        ));
    }

    #[test]
    fn resolve_with_matching_challenge_id_transitions_to_approved() {
        let cid = "018f4c1a-0000-7000-8000-000000000010";
        let mut r = make_request();
        r.issue_challenge(make_challenge(cid)).expect("issue");
        r.operator_confirmation.oob_ack = true;
        let resolution = make_resolution(cid, OobChallengeOutcome::Approved);
        let auth = r
            .resolve(resolution, RevealAuthorization::Allow)
            .expect("resolve");
        assert!(auth.is_allowed());
        assert_eq!(r.state, RevealState::Approved);
    }

    #[test]
    fn resolve_with_mismatched_challenge_id_errors() {
        let cid_a = "018f4c1a-0000-7000-8000-000000000010";
        let cid_b = "018f4c1a-0000-7000-8000-000000000011";
        let mut r = make_request();
        r.issue_challenge(make_challenge(cid_a)).expect("issue");
        let resolution = make_resolution(cid_b, OobChallengeOutcome::Approved);
        let err = r
            .resolve(resolution, RevealAuthorization::Allow)
            .expect_err("mismatch");
        assert!(matches!(err, DomainError::ChallengeMismatch { .. }));
    }

    #[test]
    fn resolve_denied_transitions_to_denied() {
        let cid = "018f4c1a-0000-7000-8000-000000000010";
        let mut r = make_request();
        r.issue_challenge(make_challenge(cid)).expect("issue");
        let resolution = make_resolution(cid, OobChallengeOutcome::Denied);
        let auth = r
            .resolve(
                resolution,
                RevealAuthorization::Deny {
                    reason: DenialReason::new("oob_denied"),
                },
            )
            .expect("resolve");
        assert!(!auth.is_allowed());
        assert_eq!(r.state, RevealState::Denied);
    }

    #[test]
    fn expire_from_pending_transitions_to_expired() {
        let mut r = make_request();
        r.expire().expect("expire");
        assert_eq!(r.state, RevealState::Expired);
    }

    #[test]
    fn expire_from_approved_is_error() {
        let cid = "018f4c1a-0000-7000-8000-000000000010";
        let mut r = make_request();
        r.issue_challenge(make_challenge(cid)).expect("issue");
        r.operator_confirmation.oob_ack = true;
        let resolution = make_resolution(cid, OobChallengeOutcome::Approved);
        r.resolve(resolution, RevealAuthorization::Allow)
            .expect("resolve");
        let err = r.expire().expect_err("expire from approved");
        assert!(matches!(
            err,
            DomainError::InvalidStateTransition(_, "expire")
        ));
    }

    #[test]
    fn empty_reason_can_be_detected() {
        // The aggregate does not enforce this — callers (factory/use-case) do.
        // This test ensures an empty string is constructible and detectable.
        let r = RevealRequest {
            id: UuidV7::new(),
            session_id: UuidV7::new(),
            handle: "vault://prod/ssh-key/bastion"
                .parse::<Handle>()
                .expect("parse"),
            reason: String::new(),
            operator_confirmation: OperatorConfirmation {
                slash_command: true,
                oob_ack: false,
                signed_config_flag: None,
            },
            created_at: Rfc3339Timestamp::now(),
            state: RevealState::Pending,
            challenge: None,
            resolution: None,
        };
        assert!(r.reason.is_empty());
    }
}
