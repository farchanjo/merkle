//! `OobResolution` — resolved Out-of-Band confirmation challenge.

use merkle_types::{ChallengeId, OobChallengeOutcome, Rfc3339Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// The outcome of an OOB Confirmation challenge, returned by the Companion
/// Device after the operator takes an action on the out-of-band channel.
///
/// ## Invariant
///
/// When `outcome == Expired`, both `device_signature` and `authorized_at`
/// MUST be `None`.  Calling [`OobResolution::new`] with a violated invariant
/// returns [`DomainError::OobResolutionInvariantViolated`].
///
/// ```
/// use merkle_types::{ChallengeId, OobChallengeOutcome};
/// use merkle_domain_access_mediation::oob::resolution::OobResolution;
///
/// let r = OobResolution::new(
///     "018f4c1a-0000-7000-8000-000000000000".parse::<ChallengeId>().unwrap(),
///     OobChallengeOutcome::Expired,
///     None,
///     None,
/// ).unwrap();
/// assert!(r.device_signature.is_none());
/// assert!(r.authorized_at.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OobResolution {
    /// UUIDv7 tying this resolution to the originating challenge.
    pub challenge_id: ChallengeId,
    /// Whether the operator approved, denied, or let the challenge expire.
    pub outcome: OobChallengeOutcome,
    /// RFC 3339 timestamp when the operator acknowledged; present only when
    /// `outcome == Approved`.
    pub authorized_at: Option<Rfc3339Timestamp>,
    /// 64-byte Ed25519 signature over the canonical challenge bytes per
    /// ADR-0011 Amendment.  Present only when `outcome == Approved` and the
    /// Companion Device produced a valid signature.
    ///
    /// The Vault Agent verifies this against the enrolled device's public key
    /// before completing the Reveal.
    ///
    /// Serialized as a lowercase hex string to avoid the serde array-size
    /// limit (serde only implements `[T; N]` for `N <= 32`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "sig_bytes_opt"
    )]
    pub device_signature: Option<[u8; 64]>,
}

/// Serde helper: serialize/deserialize `Option<[u8; 64]>` as an optional
/// lowercase hex string.
mod sig_bytes_opt {
    use serde::{Deserialize as _, Deserializer, Serializer};

    #[expect(
        clippy::ref_option,
        reason = "serde's `with` protocol requires `&Option<T>` — the more idiomatic `Option<&T>` would break the macro-generated call site"
    )]
    pub fn serialize<S: Serializer>(v: &Option<[u8; 64]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_some(&hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 64]>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let arr: [u8; 64] = v.try_into().map_err(|_| {
                    serde::de::Error::custom("expected 64 bytes for device_signature")
                })?;
                Ok(Some(arr))
            }
        }
    }
}

impl OobResolution {
    /// Construct an `OobResolution`, enforcing the expired-outcome invariant.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::OobResolutionInvariantViolated`] when
    /// `outcome == Expired` and `device_signature` is `Some`.
    pub fn new(
        challenge_id: ChallengeId,
        outcome: OobChallengeOutcome,
        authorized_at: Option<Rfc3339Timestamp>,
        device_signature: Option<[u8; 64]>,
    ) -> Result<Self, DomainError> {
        if outcome == OobChallengeOutcome::Expired && device_signature.is_some() {
            return Err(DomainError::OobResolutionInvariantViolated);
        }
        Ok(Self {
            challenge_id,
            outcome,
            authorized_at,
            device_signature,
        })
    }

    /// Returns `true` when the resolution carries an approved outcome.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        self.outcome == OobChallengeOutcome::Approved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_types::{ChallengeId, OobChallengeOutcome, Rfc3339Timestamp};

    fn cid() -> ChallengeId {
        "018f4c1a-0000-7000-8000-000000000000"
            .parse()
            .expect("parse challenge id")
    }

    #[test]
    fn approved_with_signature_is_valid() {
        let r = OobResolution::new(
            cid(),
            OobChallengeOutcome::Approved,
            Some(Rfc3339Timestamp::now()),
            Some([0u8; 64]),
        );
        assert!(r.is_ok());
        assert!(r.expect("ok").is_approved());
    }

    #[test]
    fn denied_without_signature_is_valid() {
        let r = OobResolution::new(cid(), OobChallengeOutcome::Denied, None, None);
        assert!(r.is_ok());
        assert!(!r.expect("ok").is_approved());
    }

    #[test]
    fn expired_without_signature_is_valid() {
        let r = OobResolution::new(cid(), OobChallengeOutcome::Expired, None, None);
        assert!(r.is_ok());
    }

    #[test]
    fn expired_with_signature_is_invariant_violation() {
        let r = OobResolution::new(cid(), OobChallengeOutcome::Expired, None, Some([0u8; 64]));
        assert!(matches!(
            r,
            Err(DomainError::OobResolutionInvariantViolated)
        ));
    }

    #[test]
    fn serde_json_round_trip() {
        let r = OobResolution::new(
            cid(),
            OobChallengeOutcome::Approved,
            Some(Rfc3339Timestamp::now()),
            Some([0xAA; 64]),
        )
        .expect("valid");
        let json = serde_json::to_string(&r).expect("serialize");
        let back: OobResolution = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(r.challenge_id, back.challenge_id);
        assert_eq!(r.outcome, back.outcome);
    }
}
