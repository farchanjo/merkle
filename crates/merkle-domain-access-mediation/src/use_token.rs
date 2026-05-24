//! `UseToken` — short-lived opaque authorization entity.

use std::fmt;

use base64::engine::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use merkle_types::{Handle, Rfc3339Timestamp, SecretId, UuidV7};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// Short-lived (default TTL 60 seconds), single-use authorization token issued
/// by `vault.use(handle, purpose)`.
///
/// The token is 256 bits of cryptographically random data represented as a
/// 43-character URL-safe base64 string.  It is resolved by authenticated
/// consumer processes over the Companion Socket — it is NEVER returned to the
/// MCP transport or the LLM conversation.
///
/// ## Invariants
///
/// 1. A `UseToken` is consumed exactly once; [`UseToken::consume`] returns
///    [`DomainError::TokenAlreadyConsumed`] on the second call.
/// 2. Default TTL is 60 seconds; maximum is 300 seconds.
/// 3. The Handle encoded in the token must match the Handle presented at the
///    Companion Socket on resolution.
///
/// ## Debug redaction
///
/// The `Debug` implementation redacts the raw `token` bytes to prevent
/// accidental exposure in log output.
///
/// ```
/// use merkle_types::{Handle, Rfc3339Timestamp, SecretId, UuidV7};
/// use merkle_domain_access_mediation::use_token::UseToken;
///
/// // UseToken::new constructs a valid, unconsumed token.
/// let token = UseToken::new(
///     [0u8; 32],
///     "018f4c1a-0000-7000-8000-000000000099".parse::<SecretId>().unwrap(),
///     UuidV7::new(),
///     "vault://prod/ssh-key/bastion".parse::<Handle>().unwrap(),
///     Rfc3339Timestamp::now(),
///     Rfc3339Timestamp::now(),
/// );
/// // Debug output redacts the token bytes.
/// let debug = format!("{token:?}");
/// assert!(debug.contains("REDACTED"));
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct UseToken {
    /// 256-bit (32-byte) cryptographically random token value.
    #[serde(with = "hex_bytes")]
    pub token: [u8; 32],
    /// The Secret this token grants access to.
    pub secret_id: SecretId,
    /// The MCP session that issued this token.
    pub session_id: UuidV7,
    /// The Handle being authorized; must match the Handle presented at the
    /// Companion Socket on resolution.
    pub handle: Handle,
    /// RFC 3339 timestamp when the token was issued.
    pub issued_at: Rfc3339Timestamp,
    /// RFC 3339 timestamp after which the token is invalid.
    pub expires_at: Rfc3339Timestamp,
    /// Whether the token has been consumed.
    consumed: bool,
}

impl fmt::Debug for UseToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UseToken")
            .field("token", &"REDACTED")
            .field("secret_id", &self.secret_id)
            .field("session_id", &self.session_id)
            .field("handle", &self.handle)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("consumed", &self.consumed)
            .finish()
    }
}

impl fmt::Display for UseToken {
    /// Formats the token as a URL-safe base64 string (43 characters).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&URL_SAFE_NO_PAD.encode(self.token))
    }
}

impl UseToken {
    /// Construct a new, unconsumed `UseToken`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: [u8; 32],
        secret_id: SecretId,
        session_id: UuidV7,
        handle: Handle,
        issued_at: Rfc3339Timestamp,
        expires_at: Rfc3339Timestamp,
    ) -> Self {
        Self {
            token,
            secret_id,
            session_id,
            handle,
            issued_at,
            expires_at,
            consumed: false,
        }
    }

    /// Returns `true` when this token has already been consumed.
    #[must_use]
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// Consume the token, marking it as spent.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::TokenAlreadyConsumed`] if the token was already
    /// consumed.
    pub fn consume(&mut self) -> Result<(), DomainError> {
        if self.consumed {
            return Err(DomainError::TokenAlreadyConsumed);
        }
        self.consumed = true;
        Ok(())
    }
}

/// Serde helper that encodes `[u8; 32]` as a lowercase hex string.
mod hex_bytes {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_types::{Handle, Rfc3339Timestamp, SecretId, UuidV7};

    fn make_token() -> UseToken {
        UseToken::new(
            [0xAB; 32],
            "018f4c1a-0000-7000-8000-000000000099"
                .parse::<SecretId>()
                .expect("parse secret_id"),
            UuidV7::new(),
            "vault://prod/ssh-key/bastion"
                .parse::<Handle>()
                .expect("parse handle"),
            Rfc3339Timestamp::now(),
            Rfc3339Timestamp::now(),
        )
    }

    #[test]
    fn consume_once_succeeds() {
        let mut t = make_token();
        t.consume().expect("first consume");
        assert!(t.is_consumed());
    }

    #[test]
    fn consume_twice_is_error() {
        let mut t = make_token();
        t.consume().expect("first consume");
        let err = t.consume().expect_err("second consume");
        assert!(matches!(err, DomainError::TokenAlreadyConsumed));
    }

    #[test]
    fn display_is_base64url_43_chars() {
        let t = make_token();
        let s = t.to_string();
        assert_eq!(s.len(), 43, "expected 43 base64url chars, got {}", s.len());
    }

    #[test]
    fn debug_redacts_token() {
        let t = make_token();
        let debug = format!("{t:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("abab"));
    }

    #[test]
    fn serde_json_round_trip() {
        let t = make_token();
        let json = serde_json::to_string(&t).expect("serialize");
        let back: UseToken = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(t.token, back.token);
        assert_eq!(t.session_id, back.session_id);
    }
}
