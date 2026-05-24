//! Minimal Ed25519 JWT attestation verifier (ADR-0011 Amendment 6).
//!
//! Verifies a `signed_config_flag` JWT produced by non-Claude MCP clients.
//! Deliberately avoids adding the heavy `jsonwebtoken` crate; instead uses
//! `ed25519-dalek` + `base64` + `serde_json` directly.
//!
//! # Wire format
//!
//! Compact serialisation: `base64url(header).base64url(payload).base64url(sig)`.
//!
//! Header MUST contain `"alg":"EdDSA"` and `"kid":"merkle-operator-attestation"`.
//!
//! Required payload claims:
//! - `aud`: MUST equal `"merkle-vault"`.
//! - `exp`: MUST be a future Unix timestamp.
//! - `challenge_id`: MUST match the `ChallengeId` supplied by the caller.
//!
//! Signing input: the UTF-8 bytes of `<header_b64url>.<payload_b64url>`.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use merkle_types::{ChallengeId, Rfc3339Timestamp};
use serde::Deserialize;

use crate::AppError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A raw JWT string plus its declared `kid`.
///
/// The `kid` is parsed from the JWT header before signature verification so
/// the caller can select the correct verification key.
#[derive(Debug, Clone)]
pub struct SignedConfigFlag {
    /// The compact-serialised JWT (three base64url-encoded segments).
    pub jwt: String,
    /// Key identifier declared in the JWT header.
    pub key_id: String,
}

impl SignedConfigFlag {
    /// Construct a `SignedConfigFlag`, parsing the `kid` from the JWT header.
    ///
    /// # Errors
    ///
    /// Returns `AppError::InvalidInput` when the JWT is malformed.
    pub fn parse(jwt: String) -> Result<Self, AppError> {
        let kid = extract_kid(&jwt)?;
        Ok(Self { jwt, key_id: kid })
    }
}

/// The 32-byte Ed25519 public key used to verify operator attestation JWTs.
///
/// Loaded from the OS keychain at `service="dev.fapp.merkle"`,
/// `account="merkle-operator-attestation"`.
#[derive(Debug, Clone)]
pub struct Ed25519PublicKey(pub [u8; 32]);

// ---------------------------------------------------------------------------
// Stateless verifier
// ---------------------------------------------------------------------------

/// Stateless verifier for `signed_config_flag` JWTs.
pub struct JwtAttestationVerifier;

impl JwtAttestationVerifier {
    /// Verify a `signed_config_flag` JWT.
    ///
    /// Checks (in order):
    /// 1. `alg = "EdDSA"` in header.
    /// 2. Public key is enrolled (`operator_pubkey` is non-zero).
    /// 3. Ed25519 signature over `header_b64url.payload_b64url`.
    /// 4. `aud = "merkle-vault"`.
    /// 5. `exp` is in the future relative to `now`.
    /// 6. `challenge_id` payload claim matches the supplied `challenge_id`.
    ///
    /// # Errors
    ///
    /// Returns `AppError::PolicyDenied` with a canonical sub-reason on any
    /// failure (see ADR-0011 Amendment 6 failure-mode table).
    pub fn verify(
        flag: &SignedConfigFlag,
        challenge_id: &ChallengeId,
        operator_pubkey: &Ed25519PublicKey,
        now: &Rfc3339Timestamp,
    ) -> Result<(), AppError> {
        // Split compact JWT into header / payload / signature segments.
        let parts: Vec<&str> = flag.jwt.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(AppError::PolicyDenied(
                "invalid_signed_config_flag: malformed JWT".into(),
            ));
        }
        let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

        // Decode and parse header.
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| AppError::PolicyDenied("invalid_signed_config_flag".into()))?;
        let header: JwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|_| AppError::PolicyDenied("invalid_signed_config_flag".into()))?;

        if header.alg != "EdDSA" {
            return Err(AppError::PolicyDenied(
                "invalid_signed_config_flag: alg must be EdDSA".into(),
            ));
        }

        // Verify the key is enrolled (non-zero 32 bytes).
        if operator_pubkey.0 == [0u8; 32] {
            return Err(AppError::PolicyDenied(
                "invalid_signed_config_flag: key_not_enrolled".into(),
            ));
        }

        // Verify Ed25519 signature over `header_b64.payload_b64`.
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| AppError::PolicyDenied("signature_invalid".into()))?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AppError::PolicyDenied("signature_invalid".into()))?;
        let signature = Signature::from_bytes(&sig_array);
        let verifying_key = VerifyingKey::from_bytes(&operator_pubkey.0)
            .map_err(|_| AppError::PolicyDenied("signature_invalid".into()))?;

        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| AppError::PolicyDenied("signature_invalid".into()))?;

        // Decode and parse payload.
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| AppError::PolicyDenied("invalid_signed_config_flag".into()))?;
        let payload: JwtPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|_| AppError::PolicyDenied("invalid_signed_config_flag".into()))?;

        // Validate audience.
        if payload.aud != "merkle-vault" {
            return Err(AppError::PolicyDenied("wrong_audience".into()));
        }

        // Validate expiry.
        let now_unix = now.inner().timestamp();
        if payload.exp <= now_unix {
            return Err(AppError::PolicyDenied("expired".into()));
        }

        // Validate challenge_id.
        let challenge_str = challenge_id.to_string();
        if payload.challenge_id.as_deref() != Some(challenge_str.as_str()) {
            return Err(AppError::PolicyDenied("challenge_mismatch".into()));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Compact JWT header claims (only the fields we inspect).
#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    #[allow(dead_code)]
    #[serde(default)]
    kid: String,
}

/// Compact JWT payload claims (only the fields we inspect).
#[derive(Deserialize)]
struct JwtPayload {
    aud: String,
    exp: i64,
    #[serde(default)]
    challenge_id: Option<String>,
}

/// Extract the `kid` from the JWT header without full verification.
///
/// Called by [`SignedConfigFlag::parse`] to pre-populate `key_id` before
/// the caller has loaded the corresponding public key.
fn extract_kid(jwt: &str) -> Result<String, AppError> {
    let header_b64 = jwt
        .split('.')
        .next()
        .ok_or_else(|| AppError::InvalidInput("malformed JWT: no dot separator".into()))?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| AppError::InvalidInput("malformed JWT: base64url decode failed".into()))?;
    let header: JwtHeaderFull = serde_json::from_slice(&header_bytes)
        .map_err(|_| AppError::InvalidInput("malformed JWT: header parse failed".into()))?;
    Ok(header.kid)
}

#[derive(Deserialize)]
struct JwtHeaderFull {
    #[serde(default)]
    kid: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use merkle_types::{ChallengeId, Rfc3339Timestamp};

    use super::*;

    /// Build a compact JWT signed with the given signing key.
    fn build_jwt(signing_key: &SigningKey, aud: &str, exp: i64, challenge_id: &str) -> String {
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": "merkle-operator-attestation"
        });
        let payload = serde_json::json!({
            "sub": "non-claude-mcp-client",
            "iss": "test-operator",
            "aud": aud,
            "iat": exp - 60,
            "exp": exp,
            "challenge_id": challenge_id,
            "session_id": "00000000-0000-0000-0000-000000000000"
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    fn test_keys() -> (SigningKey, Ed25519PublicKey) {
        // Build a deterministic test key from a fixed seed.
        // Using a fixed seed makes tests reproducible and avoids a `rand` dev-dep.
        // SAFETY: indices are 0..31, never exceed u8::MAX even after the +1 offset.
        #[expect(clippy::cast_possible_truncation, reason = "seed indices are 0..31")]
        let seed: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_bytes = signing_key.verifying_key().to_bytes();
        (signing_key, Ed25519PublicKey(verifying_bytes))
    }

    fn test_keys_b() -> (SigningKey, Ed25519PublicKey) {
        // SAFETY: indices 0..31, wrapping_add(100) stays within 0..131.
        #[expect(clippy::cast_possible_truncation, reason = "seed indices are 0..31")]
        let seed: [u8; 32] = std::array::from_fn(|i| i as u8 + 100);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_bytes = signing_key.verifying_key().to_bytes();
        (signing_key, Ed25519PublicKey(verifying_bytes))
    }

    fn future_exp() -> i64 {
        // 5 minutes from now
        Rfc3339Timestamp::now().inner().timestamp() + 300
    }

    #[test]
    fn valid_jwt_returns_ok() {
        let (signing_key, pubkey) = test_keys();
        let challenge = ChallengeId::new();
        let jwt = build_jwt(
            &signing_key,
            "merkle-vault",
            future_exp(),
            &challenge.to_string(),
        );
        let flag = SignedConfigFlag {
            jwt,
            key_id: "merkle-operator-attestation".into(),
        };
        let now = Rfc3339Timestamp::now();
        let result = JwtAttestationVerifier::verify(&flag, &challenge, &pubkey, &now);
        assert!(result.is_ok(), "valid JWT must verify: {result:?}");
    }

    #[test]
    fn wrong_signing_key_returns_signature_invalid() {
        let (signing_key, _pubkey) = test_keys();
        let (_other_sk, other_pubkey) = test_keys_b();
        let challenge = ChallengeId::new();
        let jwt = build_jwt(
            &signing_key,
            "merkle-vault",
            future_exp(),
            &challenge.to_string(),
        );
        let flag = SignedConfigFlag {
            jwt,
            key_id: "merkle-operator-attestation".into(),
        };
        let now = Rfc3339Timestamp::now();
        let result = JwtAttestationVerifier::verify(&flag, &challenge, &other_pubkey, &now);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("signature_invalid"),
            "wrong key must produce signature_invalid; got: {err}"
        );
    }

    #[test]
    fn expired_jwt_returns_expired() {
        let (signing_key, pubkey) = test_keys();
        let challenge = ChallengeId::new();
        // exp 1 second in the past
        let past_exp = Rfc3339Timestamp::now().inner().timestamp() - 1;
        let jwt = build_jwt(
            &signing_key,
            "merkle-vault",
            past_exp,
            &challenge.to_string(),
        );
        let flag = SignedConfigFlag {
            jwt,
            key_id: "merkle-operator-attestation".into(),
        };
        let now = Rfc3339Timestamp::now();
        let result = JwtAttestationVerifier::verify(&flag, &challenge, &pubkey, &now);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("expired"),
            "past exp must produce expired; got: {err}"
        );
    }

    #[test]
    fn wrong_audience_returns_wrong_audience() {
        let (signing_key, pubkey) = test_keys();
        let challenge = ChallengeId::new();
        let jwt = build_jwt(
            &signing_key,
            "other-service",
            future_exp(),
            &challenge.to_string(),
        );
        let flag = SignedConfigFlag {
            jwt,
            key_id: "merkle-operator-attestation".into(),
        };
        let now = Rfc3339Timestamp::now();
        let result = JwtAttestationVerifier::verify(&flag, &challenge, &pubkey, &now);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("wrong_audience"),
            "wrong aud must produce wrong_audience; got: {err}"
        );
    }

    #[test]
    fn challenge_mismatch_returns_challenge_mismatch() {
        let (signing_key, pubkey) = test_keys();
        let challenge_in_jwt = ChallengeId::new();
        let different_challenge = ChallengeId::new();
        let jwt = build_jwt(
            &signing_key,
            "merkle-vault",
            future_exp(),
            &challenge_in_jwt.to_string(),
        );
        let flag = SignedConfigFlag {
            jwt,
            key_id: "merkle-operator-attestation".into(),
        };
        let now = Rfc3339Timestamp::now();
        let result = JwtAttestationVerifier::verify(&flag, &different_challenge, &pubkey, &now);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("challenge_mismatch"),
            "mismatched challenge must produce challenge_mismatch; got: {err}"
        );
    }

    #[test]
    fn zero_pubkey_returns_key_not_enrolled() {
        let (signing_key, _pubkey) = test_keys();
        let challenge = ChallengeId::new();
        let jwt = build_jwt(
            &signing_key,
            "merkle-vault",
            future_exp(),
            &challenge.to_string(),
        );
        let flag = SignedConfigFlag {
            jwt,
            key_id: "merkle-operator-attestation".into(),
        };
        let zero_key = Ed25519PublicKey([0u8; 32]);
        let now = Rfc3339Timestamp::now();
        let result = JwtAttestationVerifier::verify(&flag, &challenge, &zero_key, &now);
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("key_not_enrolled"),
            "zero key must produce key_not_enrolled; got: {err}"
        );
    }
}
