//! `VaultRootKey` entity — 32-byte key protecting all Namespace DEKs.
//!
//! Mirrors `docs/arch/schemas/identity_and_sealing/vault_root_key.cue`.
//!
//! The key material is held in a `secrecy::SecretBox<[u8; 32]>` and zeroed on
//! drop.  `Debug` never exposes the bytes.  The wrapped-key form is defined by
//! [`WrappedVaultRootKey`], which carries only ciphertext and is safe to
//! persist.

use std::fmt;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use merkle_types::Rfc3339Timestamp;

use crate::master_key::MasterKey;

// ---------------------------------------------------------------------------
// WrapMethod
// ---------------------------------------------------------------------------

/// The wrapping key used to produce a [`WrappedVaultRootKey`].
///
/// Per the domain invariant the Vault Root Key is always dual-wrapped:
/// one copy under the `MasterKey` and one under the `RecoveryPublicKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WrapMethod {
    /// Wrapped with the active `MasterKey` (primary unlock path).
    MasterKey,
    /// Wrapped with the Recovery Public Key (disaster-recovery path).
    RecoveryPublicKey,
}

// ---------------------------------------------------------------------------
// WrappedVaultRootKey
// ---------------------------------------------------------------------------

/// The ciphertext produced by wrapping the Vault Root Key under a key holder.
///
/// This is the form persisted to the database.  The `ciphertext` contains
/// `nonce || encrypted_key_bytes || poly1305_tag` for XChaCha20-Poly1305.
///
/// **Never** holds plaintext key material.  Constructed by the crypto adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedVaultRootKey {
    /// AEAD ciphertext (nonce‖ciphertext‖tag for XChaCha20-Poly1305).
    pub ciphertext: Vec<u8>,

    /// 24-byte XChaCha20-Poly1305 nonce.
    pub nonce: [u8; 24],

    /// Wrapping key identity.
    pub wrapped_by: WrapMethod,

    /// Monotonically increasing version counter, starting at 1.
    pub version: u32,

    /// Timestamp of wrapping.
    pub created_at: Rfc3339Timestamp,
}

// ---------------------------------------------------------------------------
// VaultRootKey
// ---------------------------------------------------------------------------

/// The 32-byte symmetric key that protects all Namespace DEKs.
///
/// Held in `secrecy::SecretBox` for automatic zeroize-on-drop.  `Debug` prints
/// `VaultRootKey([REDACTED])`.  `Display` is intentionally not implemented.
///
/// The only way to produce key material from this struct is [`expose`](Self::expose),
/// which returns a [`secrecy::ExposeSecret`]-gated reference.
///
/// ```
/// use merkle_domain_identity::VaultRootKey;
///
/// let vrk = VaultRootKey::generate();
/// let debug = format!("{vrk:?}");
/// assert_eq!(debug, "VaultRootKey([REDACTED])");
/// ```
pub struct VaultRootKey {
    inner: secrecy::SecretBox<[u8; 32]>,
}

impl fmt::Debug for VaultRootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultRootKey([REDACTED])")
    }
}

impl VaultRootKey {
    /// Generate a fresh `VaultRootKey` using the OS random number generator.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self {
            inner: secrecy::SecretBox::new(Box::new(bytes)),
        }
    }

    /// Construct from raw bytes recovered after unwrapping a
    /// [`WrappedVaultRootKey`].
    ///
    /// The bytes are immediately placed in a `SecretBox`; the original buffer
    /// is consumed (and therefore no longer accessible in the caller).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            inner: secrecy::SecretBox::new(Box::new(bytes)),
        }
    }

    /// Expose the secret bytes for cryptographic operations.
    ///
    /// The returned reference is scoped to `self`.  Do not store it, log it,
    /// or transmit it outside the current call stack.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        use secrecy::ExposeSecret;
        self.inner.expose_secret()
    }

    /// Produce a stub `WrappedVaultRootKey` for the given `MasterKey`.
    ///
    /// This method defines the signature contract for wrapping.  The actual
    /// XChaCha20-Poly1305 encryption is performed by the crypto adapter.
    /// For now this returns a placeholder with a zeroed nonce and empty
    /// ciphertext so that callers can compile against the interface.
    ///
    /// **The returned value is NOT cryptographically secure.**  Replace with
    /// the adapter-supplied implementation before shipping.
    ///
    /// The `self` parameter is present so that the real adapter implementation
    /// can access the plaintext bytes via `self.expose()`.  The stub discards
    /// the key material intentionally.
    #[must_use]
    #[expect(
        clippy::unused_self,
        reason = "stub: real adapter uses self.expose() here"
    )]
    pub fn wrap_with_stub(&self, master_key: &MasterKey, version: u32) -> WrappedVaultRootKey {
        // The real crypto adapter will call AEAD-encrypt here.  This stub
        // exists purely so callers compile.
        let _ = master_key; // adapter uses this for AEAD-encrypt
        WrappedVaultRootKey {
            ciphertext: Vec::new(),
            nonce: [0u8; 24],
            wrapped_by: WrapMethod::MasterKey,
            version,
            created_at: Rfc3339Timestamp::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_unique_keys() {
        let a = VaultRootKey::generate();
        let b = VaultRootKey::generate();
        // Two independent generations should (overwhelmingly) differ.
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn from_bytes_round_trip() {
        let bytes = [0xCAu8; 32];
        let vrk = VaultRootKey::from_bytes(bytes);
        assert_eq!(vrk.expose(), &bytes);
    }

    #[test]
    fn debug_redacts_bytes() {
        let vrk = VaultRootKey::generate();
        assert_eq!(format!("{vrk:?}"), "VaultRootKey([REDACTED])");
    }

    #[test]
    fn wrap_with_stub_returns_master_key_method() {
        let vrk = VaultRootKey::generate();
        let mk = MasterKey::new(1, Rfc3339Timestamp::now());
        let wrapped = vrk.wrap_with_stub(&mk, 1);
        assert_eq!(wrapped.wrapped_by, WrapMethod::MasterKey);
        assert_eq!(wrapped.version, 1);
    }
}
