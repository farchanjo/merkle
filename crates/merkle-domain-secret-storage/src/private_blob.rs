//! `PrivateBlob` — the encrypted envelope for Secret material.
//!
//! A `PrivateBlob` holds the XChaCha20-Poly1305 ciphertext, the 24-byte nonce,
//! the 16-byte AEAD authentication tag, and the Associated Data (AD) bytes.
//!
//! The AD is always the UTF-8 bytes of the Handle URI
//! (`vault://<ns>/<cat>/<name>`), binding the ciphertext to the specific Secret
//! identity and preventing cross-secret ciphertext substitution.
//!
//! # Debug redaction
//!
//! `Debug` for `PrivateBlob` never prints the ciphertext content — it shows
//! only the ciphertext byte length. This prevents accidental exposure in logs.

use std::fmt;

use merkle_types::Handle;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::error::DomainError;

/// The encrypted envelope wrapping a Secret's sensitive material.
///
/// Wire format (stored): `nonce (24 bytes) || ciphertext || Poly1305 tag (16 bytes)`.
///
/// The `ciphertext` field stores only the ciphertext bytes (without nonce or
/// tag prefixed); `nonce` and `aead_tag` are stored in separate fields for
/// clarity and schema alignment.
///
/// # Invariants
///
/// - `nonce` is exactly 24 bytes (XChaCha20 nonce length).
/// - `aead_tag` is exactly 16 bytes (Poly1305 tag length).
/// - `associated_data` is the UTF-8 encoding of the Handle URI.
/// - The struct never stores plaintext; the encryption happens outside this type.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct PrivateBlob {
    /// The raw ciphertext bytes produced by XChaCha20-Poly1305 AEAD.
    pub ciphertext: Vec<u8>,

    /// The 24-byte random nonce used for this encryption.
    ///
    /// A fresh nonce MUST be generated for every write; nonce reuse with the
    /// same Namespace DEK is a critical fault.
    pub nonce: [u8; 24],

    /// The 16-byte Poly1305 authentication tag.
    pub aead_tag: [u8; 16],

    /// The Associated Data used during encryption.
    ///
    /// Always set to the UTF-8 bytes of the Handle URI
    /// (`vault://<namespace>/<category>/<name>`).
    pub associated_data: Vec<u8>,

    /// The version of the Namespace DEK used to encrypt this blob.
    ///
    /// Required for DEK rotation and re-wrapping operations.
    pub dek_version: u32,
}

impl PrivateBlob {
    /// Construct a new `PrivateBlob`.
    ///
    /// Callers provide pre-computed ciphertext and AEAD tag produced by the
    /// `CryptoPort`; this constructor is intentionally low-level. The
    /// `associated_data` must be the UTF-8 encoding of the Handle URI.
    #[must_use]
    pub fn new(
        ciphertext: Vec<u8>,
        nonce: [u8; 24],
        aead_tag: [u8; 16],
        associated_data: Vec<u8>,
        dek_version: u32,
    ) -> Self {
        Self {
            ciphertext,
            nonce,
            aead_tag,
            associated_data,
            dek_version,
        }
    }

    /// Verify that the stored Associated Data matches the expected Handle URI.
    ///
    /// Returns [`DomainError::AdBindingMismatch`] when the bytes differ.
    ///
    /// # Errors
    ///
    /// Returns an error if `self.associated_data` does not equal the UTF-8
    /// representation of `expected_handle`.
    pub fn verify_ad(&self, expected_handle: &Handle) -> Result<(), DomainError> {
        let expected_bytes = expected_handle.to_string().into_bytes();
        if self.associated_data == expected_bytes {
            Ok(())
        } else {
            Err(DomainError::AdBindingMismatch {
                expected: expected_handle.to_string(),
            })
        }
    }

    /// Return the ciphertext length in bytes.
    ///
    /// Use this instead of inspecting `ciphertext` directly in log statements
    /// to prevent accidental data exposure.
    #[must_use]
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }
}

impl fmt::Debug for PrivateBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateBlob")
            .field(
                "ciphertext",
                &format_args!("<{} bytes>", self.ciphertext.len()),
            )
            .field("nonce", &"<24 bytes>")
            .field("aead_tag", &"<16 bytes>")
            .field("associated_data_len", &self.associated_data.len())
            .field("dek_version", &self.dek_version)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_types::{CategoryName, Handle, NamespaceLabel, SecretName};

    fn make_handle() -> Handle {
        Handle::new(
            "my-ns".parse::<NamespaceLabel>().expect("valid ns"),
            "ssh".parse::<CategoryName>().expect("valid cat"),
            "my-key".parse::<SecretName>().expect("valid name"),
        )
    }

    fn make_blob(handle: &Handle) -> PrivateBlob {
        let ad = handle.to_string().into_bytes();
        PrivateBlob::new(vec![0xAB; 32], [0u8; 24], [0u8; 16], ad, 1)
    }

    #[test]
    fn verify_ad_succeeds_for_matching_handle() {
        let handle = make_handle();
        let blob = make_blob(&handle);
        assert!(blob.verify_ad(&handle).is_ok());
    }

    #[test]
    fn verify_ad_fails_for_different_handle() {
        let handle = make_handle();
        let blob = make_blob(&handle);
        let other_handle = Handle::new(
            "other-ns".parse::<NamespaceLabel>().expect("valid ns"),
            "ssh".parse::<CategoryName>().expect("valid cat"),
            "my-key".parse::<SecretName>().expect("valid name"),
        );
        assert!(blob.verify_ad(&other_handle).is_err());
    }

    #[test]
    fn debug_does_not_expose_ciphertext() {
        let handle = make_handle();
        let blob = make_blob(&handle);
        let debug = format!("{blob:?}");
        // The raw ciphertext bytes (0xAB = 171 decimal) must NOT appear verbatim.
        assert!(
            !debug.contains("171, 171"),
            "ciphertext leaked in Debug output"
        );
        assert!(
            debug.contains("32 bytes"),
            "ciphertext length should appear"
        );
    }

    #[test]
    fn ciphertext_len_returns_correct_value() {
        let handle = make_handle();
        let blob = make_blob(&handle);
        assert_eq!(blob.ciphertext_len(), 32);
    }
}
