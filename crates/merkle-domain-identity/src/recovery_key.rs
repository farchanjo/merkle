//! `RecoveryKey` entity — age X25519 identity (public side only).
//!
//! Mirrors `docs/arch/schemas/identity_and_sealing/recovery_key.cue`.
//!
//! **SECURITY:** The private age secret key is NEVER stored by the system.
//! Only the public recipient (`age1...`) and its fingerprint are persisted here.
//! The private key is shown once at `merkle init` and remains exclusively in
//! the operator's custody.

use std::fmt;

use serde::{Deserialize, Serialize};

use merkle_types::Rfc3339Timestamp;

/// The public half of the age X25519 recovery identity.
///
/// Stores the bech32 public recipient and its SHA-256 fingerprint.  The
/// private key is never held by the system.
///
/// `Display` renders a summary that DOES NOT include any key bytes.
/// `Debug` is manually implemented for the same reason.
///
/// ```
/// use merkle_domain_identity::RecoveryPublicKey;
/// use merkle_types::Rfc3339Timestamp;
///
/// let rpk = RecoveryPublicKey::new(
///     "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_owned(),
///     "SHA256:abc123def=".to_owned(),
///     Rfc3339Timestamp::now(),
/// );
/// assert!(rpk.to_string().contains("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"));
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryPublicKey {
    /// age bech32 recipient derived from the secret key (`age1...`).
    identity_pubkey: String,

    /// SHA-256 fingerprint of the public key in `"SHA256:<base64>"` notation.
    fingerprint: String,

    /// Timestamp of recovery key generation.
    created_at: Rfc3339Timestamp,

    /// Timestamp of supersession (operator-initiated rotation).
    #[serde(skip_serializing_if = "Option::is_none")]
    rotated_at: Option<Rfc3339Timestamp>,
}

impl fmt::Debug for RecoveryPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryPublicKey")
            .field("identity_pubkey", &self.identity_pubkey)
            .field("fingerprint", &self.fingerprint)
            .field("created_at", &self.created_at)
            .field("rotated_at", &self.rotated_at)
            .finish()
    }
}

impl fmt::Display for RecoveryPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RecoveryPublicKey(pubkey={}, fingerprint={})",
            self.identity_pubkey, self.fingerprint
        )
    }
}

impl RecoveryPublicKey {
    /// Construct a new `RecoveryPublicKey` from the age bech32 recipient and
    /// its fingerprint.
    #[must_use]
    pub fn new(identity_pubkey: String, fingerprint: String, created_at: Rfc3339Timestamp) -> Self {
        Self {
            identity_pubkey,
            fingerprint,
            created_at,
            rotated_at: None,
        }
    }

    /// Return the age bech32 public key recipient (`age1...`).
    #[must_use]
    pub fn identity_pubkey(&self) -> &str {
        &self.identity_pubkey
    }

    /// Return the SHA-256 fingerprint in `"SHA256:<base64>"` notation.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Return the creation timestamp.
    #[must_use]
    pub fn created_at(&self) -> Rfc3339Timestamp {
        self.created_at
    }

    /// Return the rotation timestamp, if this key has been superseded.
    #[must_use]
    pub fn rotated_at(&self) -> Option<Rfc3339Timestamp> {
        self.rotated_at
    }

    /// Mark this key as superseded.
    pub fn mark_rotated(&mut self, rotated_at: Rfc3339Timestamp) {
        self.rotated_at = Some(rotated_at);
    }
}

/// The private age X25519 identity (held exclusively by the operator).
///
/// This struct exists only as a transient carrier during the `merkle init`
/// display window and `merkle recover` command.  It is **never** serialized,
/// never stored, and its inner bytes are zeroed on drop.
///
/// The private key material is exposed only through the controlled
/// `expose_secret` method, which returns a short-lived reference.
///
/// ```
/// use merkle_domain_identity::RecoveryKey;
///
/// let key = RecoveryKey::new([0u8; 32]);
/// // The bytes are accessible for use but cannot be printed.
/// let _ = key.expose_secret();
/// ```
pub struct RecoveryKey {
    /// 32-byte X25519 secret scalar.
    secret_bytes: secrecy::SecretBox<[u8; 32]>,
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

impl RecoveryKey {
    /// Construct from raw secret bytes.
    ///
    /// The bytes are immediately moved into a `SecretBox` (zeroized on drop).
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            secret_bytes: secrecy::SecretBox::new(Box::new(bytes)),
        }
    }

    /// Expose the secret bytes for cryptographic operations.
    ///
    /// The returned reference is scoped to the lifetime of `self`.  Do not
    /// store it, log it, or transmit it outside the call stack.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        use secrecy::ExposeSecret;
        self.secret_bytes.expose_secret()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_public_key_display_does_not_panic() {
        let rpk = RecoveryPublicKey::new(
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p".to_owned(),
            "SHA256:abc123def=".to_owned(),
            Rfc3339Timestamp::now(),
        );
        let s = rpk.to_string();
        assert!(s.contains("age1"), "display must include pubkey prefix");
    }

    #[test]
    fn recovery_public_key_debug_shows_fields() {
        let rpk = RecoveryPublicKey::new(
            "age1test".to_owned(),
            "SHA256:x=".to_owned(),
            Rfc3339Timestamp::now(),
        );
        let debug = format!("{rpk:?}");
        assert!(debug.contains("age1test"));
        assert!(debug.contains("SHA256:x="));
    }

    #[test]
    fn recovery_key_debug_redacts_bytes() {
        let key = RecoveryKey::new([0xAAu8; 32]);
        let debug = format!("{key:?}");
        assert!(
            debug.contains("[REDACTED]"),
            "secret bytes must be redacted in Debug"
        );
        assert!(
            !debug.contains("170"),
            "numeric byte values must not appear"
        );
    }

    #[test]
    fn recovery_key_expose_secret_returns_bytes() {
        let bytes = [42u8; 32];
        let key = RecoveryKey::new(bytes);
        assert_eq!(key.expose_secret(), &bytes);
    }

    #[test]
    fn mark_rotated_sets_timestamp() {
        let mut rpk = RecoveryPublicKey::new(
            "age1test".to_owned(),
            "SHA256:x=".to_owned(),
            Rfc3339Timestamp::now(),
        );
        assert!(rpk.rotated_at().is_none());
        rpk.mark_rotated(Rfc3339Timestamp::now());
        assert!(rpk.rotated_at().is_some());
    }
}
