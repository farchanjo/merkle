//! `NamespaceDek` entity — per-namespace Data Encryption Key.
//!
//! Mirrors `docs/arch/schemas/identity_and_sealing/namespace_dek.cue`.
//!
//! The plaintext DEK is held in a `secrecy::SecretBox` and zeroed on drop.
//! Only the wrapped form is persisted to the database; the unwrapped key
//! lives in process memory only during the lifetime of this struct.

use std::fmt;

use serde::{Deserialize, Serialize};
use merkle_types::{NamespaceId, Rfc3339Timestamp, UuidV7};

// ---------------------------------------------------------------------------
// WrappedDek — the persistent form
// ---------------------------------------------------------------------------

/// The XChaCha20-Poly1305 ciphertext produced by encrypting a raw DEK under
/// the active `VaultRootKey`.
///
/// This is the only form that ever reaches persistent storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedDek {
    /// AEAD ciphertext: 24-byte nonce ‖ encrypted DEK ‖ 16-byte Poly1305 tag.
    pub blob: Vec<u8>,

    /// Monotonically increasing version counter within the namespace.
    pub version: u32,
}

// ---------------------------------------------------------------------------
// NamespaceDek
// ---------------------------------------------------------------------------

/// One Data Encryption Key for a single Namespace.
///
/// Encrypts the `private_blob` column for all Secrets in the owning
/// Namespace.  Wrapped by the Vault Root Key in persistent storage.
///
/// The unwrapped key material is held in a `secrecy::SecretBox` and zeroed on
/// drop.  `Debug` prints `[REDACTED]` in place of the key bytes.
///
/// **Destruction** of this record renders all corresponding private blobs
/// permanently unrecoverable unless a backup exists.  Destruction is always
/// explicit — the domain never destroys a DEK implicitly.
///
/// ```
/// use merkle_domain_identity::NamespaceDek;
/// use merkle_types::{NamespaceId, Rfc3339Timestamp, UuidV7};
///
/// let ns_id = NamespaceId::new();
/// let dek = NamespaceDek::new(ns_id, 1, [0xABu8; 32], Rfc3339Timestamp::now());
/// assert_eq!(dek.version(), 1);
/// let debug = format!("{dek:?}");
/// assert!(debug.contains("[REDACTED]"));
/// ```
#[derive(Serialize, Deserialize)]
pub struct NamespaceDek {
    /// Unique identifier for this DEK record (UUIDv7).
    id: UuidV7,

    /// The namespace that owns this DEK.
    namespace_id: NamespaceId,

    /// Monotonically increasing counter within the namespace; starts at 1.
    version: u32,

    /// Timestamp of DEK generation.
    created_at: Rfc3339Timestamp,

    /// The wrapped (persisted) form of this DEK.
    ///
    /// `None` until the crypto adapter populates it via
    /// [`NamespaceDek::set_wrapped`].
    #[serde(skip_serializing_if = "Option::is_none")]
    wrapped: Option<WrappedDek>,

    /// Plaintext 32-byte key material.
    ///
    /// Held in memory only; never serialized.  Zeroed on drop.
    #[serde(skip)]
    plaintext: Option<secrecy::SecretBox<[u8; 32]>>,
}

impl fmt::Debug for NamespaceDek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NamespaceDek")
            .field("id", &self.id)
            .field("namespace_id", &self.namespace_id)
            .field("version", &self.version)
            .field("created_at", &self.created_at)
            .field("wrapped", &self.wrapped)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}

impl Clone for NamespaceDek {
    fn clone(&self) -> Self {
        // Plaintext is intentionally NOT cloned to avoid widening the attack
        // surface.  Callers that need the unwrapped key must go through the
        // crypto adapter.
        Self {
            id: self.id,
            namespace_id: self.namespace_id,
            version: self.version,
            created_at: self.created_at,
            wrapped: self.wrapped.clone(),
            plaintext: None,
        }
    }
}

impl Drop for NamespaceDek {
    fn drop(&mut self) {
        // secrecy::SecretBox already zeroizes its contents on drop.
        // We explicitly drop here to make the intent clear.
        let _ = self.plaintext.take();
    }
}

impl NamespaceDek {
    /// Construct a new `NamespaceDek` with the given plaintext key material.
    ///
    /// The key bytes are immediately placed in a `SecretBox`; the caller's
    /// copy is consumed.
    #[must_use]
    pub fn new(
        namespace_id: NamespaceId,
        version: u32,
        key_bytes: [u8; 32],
        created_at: Rfc3339Timestamp,
    ) -> Self {
        Self {
            id: UuidV7::new(),
            namespace_id,
            version,
            created_at,
            wrapped: None,
            plaintext: Some(secrecy::SecretBox::new(Box::new(key_bytes))),
        }
    }

    /// Construct a metadata-only shell with no plaintext (used when loading
    /// the wrapped form from storage before decryption).
    #[must_use]
    pub fn from_wrapped(
        id: UuidV7,
        namespace_id: NamespaceId,
        version: u32,
        created_at: Rfc3339Timestamp,
        wrapped: WrappedDek,
    ) -> Self {
        Self {
            id,
            namespace_id,
            version,
            created_at,
            wrapped: Some(wrapped),
            plaintext: None,
        }
    }

    /// Load decrypted key material into this DEK (called by the crypto adapter).
    pub fn load_plaintext(&mut self, key_bytes: [u8; 32]) {
        self.plaintext = Some(secrecy::SecretBox::new(Box::new(key_bytes)));
    }

    /// Attach the wrapped form (called by the crypto adapter after encryption).
    pub fn set_wrapped(&mut self, wrapped: WrappedDek) {
        self.wrapped = Some(wrapped);
    }

    /// Expose the plaintext key bytes for encryption/decryption operations.
    ///
    /// Returns `None` if the plaintext has not been loaded yet.
    /// **Never** store or log the returned reference.
    #[must_use]
    pub fn expose_plaintext(&self) -> Option<&[u8; 32]> {
        self.plaintext
            .as_ref()
            .map(secrecy::ExposeSecret::expose_secret)
    }

    /// Return the unique DEK identifier.
    #[must_use]
    pub fn id(&self) -> UuidV7 {
        self.id
    }

    /// Return the owning namespace identifier.
    #[must_use]
    pub fn namespace_id(&self) -> NamespaceId {
        self.namespace_id
    }

    /// Return the version counter.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Return the creation timestamp.
    #[must_use]
    pub fn created_at(&self) -> Rfc3339Timestamp {
        self.created_at
    }

    /// Return the wrapped DEK blob, if available.
    #[must_use]
    pub fn wrapped(&self) -> Option<&WrappedDek> {
        self.wrapped.as_ref()
    }

    /// Zeroize the in-memory plaintext key bytes, returning them for
    /// diagnostic purposes.
    ///
    /// After this call `expose_plaintext` returns `None`.
    pub fn seal_plaintext(&mut self) {
        // Drop triggers zeroize via SecretBox.
        self.plaintext = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dek() -> NamespaceDek {
        NamespaceDek::new(
            NamespaceId::new(),
            1,
            [0x11u8; 32],
            Rfc3339Timestamp::now(),
        )
    }

    #[test]
    fn plaintext_exposed_after_construction() {
        let dek = make_dek();
        assert_eq!(dek.expose_plaintext(), Some(&[0x11u8; 32]));
    }

    #[test]
    fn clone_does_not_copy_plaintext() {
        let dek = make_dek();
        let cloned = dek.clone();
        assert!(cloned.expose_plaintext().is_none(), "cloned DEK must not expose plaintext");
    }

    #[test]
    fn seal_plaintext_clears_key() {
        let mut dek = make_dek();
        dek.seal_plaintext();
        assert!(dek.expose_plaintext().is_none());
    }

    #[test]
    fn debug_redacts_plaintext() {
        let dek = make_dek();
        let debug = format!("{dek:?}");
        assert!(debug.contains("[REDACTED]"));
        // The raw byte value 0x11 = 17; must not appear.
        assert!(!debug.contains("17,"), "raw byte values must not appear in debug");
    }

    #[test]
    fn version_accessor_correct() {
        let dek = make_dek();
        assert_eq!(dek.version(), 1);
    }

    #[test]
    fn set_wrapped_stores_blob() {
        let mut dek = make_dek();
        let blob = WrappedDek { blob: vec![0u8; 72], version: 1 };
        dek.set_wrapped(blob);
        assert!(dek.wrapped().is_some());
    }

    #[test]
    fn load_plaintext_allows_exposure() {
        let ns_id = NamespaceId::new();
        let wrapped = WrappedDek { blob: vec![0u8; 72], version: 1 };
        let mut dek = NamespaceDek::from_wrapped(
            UuidV7::new(),
            ns_id,
            1,
            Rfc3339Timestamp::now(),
            wrapped,
        );
        assert!(dek.expose_plaintext().is_none());
        dek.load_plaintext([0xBBu8; 32]);
        assert_eq!(dek.expose_plaintext(), Some(&[0xBBu8; 32]));
    }
}

