//! [`Crypto`] driven port — cryptographic primitive abstraction.
//!
//! Concrete implementations live in `merkle-adapter-crypto`. The trait is
//! deliberately synchronous; all operations complete in bounded time without
//! I/O, so wrapping them in `async` would add overhead with no benefit.
//!
//! Const generics on traits are dyn-hostile; fixed-size methods are used
//! instead per Rust object-safety rules.

use crate::error::CryptoError;
use merkle_domain_identity::Argon2idParams;
use merkle_types::{Blake3Hash, HmacSignature};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Ed25519 private (signing) key bytes.
///
/// Zeroized on drop to avoid leaving key material in process memory.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct Ed25519PrivateKey(
    /// Raw 32-byte seed.
    pub [u8; 32],
);

/// Ed25519 public (verification) key bytes.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Ed25519PublicKey(
    /// Raw 32-byte compressed point.
    pub [u8; 32],
);

/// X25519 private (Diffie-Hellman) key bytes.
///
/// Zeroized on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct X25519PrivateKey(
    /// Raw 32-byte scalar.
    pub [u8; 32],
);

/// X25519 public (Diffie-Hellman) key bytes.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct X25519PublicKey(
    /// Raw 32-byte compressed Montgomery point.
    pub [u8; 32],
);

/// Wire-format of an ECIES (X25519 + XChaCha20-Poly1305) encrypted envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EciesEnvelopeBytes {
    /// Ephemeral sender public key used for the DH exchange.
    pub ephemeral_pubkey: [u8; 32],
    /// XChaCha20-Poly1305 nonce (192 bits).
    pub nonce: [u8; 24],
    /// Encrypted payload (AEAD ciphertext without the tag).
    pub ciphertext: Vec<u8>,
    /// AEAD authentication tag (128 bits).
    pub aead_tag: [u8; 16],
}

/// An `age` recipient public key string (e.g. `age1...`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgeRecipient(
    /// Bech32-encoded age public key.
    pub String,
);

/// An `age` identity (private key) string.
///
/// Zeroized on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct AgeIdentity(
    /// Bech32-encoded age private key (starts with `AGE-SECRET-KEY-1`).
    pub String,
);

/// Driven port for all cryptographic operations used by Merkle.
///
/// Implementations MUST be deterministic for functions that take explicit key
/// and nonce parameters, and MUST use a cryptographically secure RNG for
/// `random_bytes_*` methods.
pub trait Crypto: Send + Sync {
    /// Encrypt `plaintext` with XChaCha20-Poly1305 using `key` and `nonce`.
    ///
    /// `aad` is additional authenticated data bound to the ciphertext tag.
    fn aead_encrypt(&self, key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt and authenticate `ciphertext` with XChaCha20-Poly1305.
    ///
    /// Returns [`CryptoError::AeadVerifyFailed`] when the tag is invalid.
    fn aead_decrypt(&self, key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Compute the unkeyed BLAKE3 hash of `data`.
    fn blake3_hash(&self, data: &[u8]) -> Blake3Hash;

    /// Compute the keyed BLAKE3 MAC of `data` using `key`.
    fn blake3_keyed(&self, key: &[u8; 32], data: &[u8]) -> HmacSignature;

    /// Derive a 32-byte key from `passphrase` using Argon2id with the given `params`.
    fn argon2id_derive(&self, passphrase: &[u8], salt: &[u8; 16], params: &Argon2idParams) -> Result<[u8; 32], CryptoError>;

    /// Generate a fresh Ed25519 keypair.
    fn ed25519_keypair(&self) -> (Ed25519PrivateKey, Ed25519PublicKey);

    /// Sign `msg` with `sk`, returning the 64-byte Ed25519 signature.
    fn ed25519_sign(&self, sk: &Ed25519PrivateKey, msg: &[u8]) -> [u8; 64];

    /// Verify an Ed25519 `sig` over `msg` using `pk`.
    fn ed25519_verify(&self, pk: &Ed25519PublicKey, msg: &[u8], sig: &[u8; 64]) -> Result<(), CryptoError>;

    /// Generate a fresh X25519 keypair.
    fn x25519_keypair(&self) -> (X25519PrivateKey, X25519PublicKey);

    /// ECIES-encrypt `plaintext` for `recipient_pk`.
    fn x25519_ecies_encrypt(&self, recipient_pk: &X25519PublicKey, plaintext: &[u8], aad: &[u8]) -> Result<EciesEnvelopeBytes, CryptoError>;

    /// ECIES-decrypt `envelope` using `recipient_sk`.
    fn x25519_ecies_decrypt(&self, recipient_sk: &X25519PrivateKey, envelope: &EciesEnvelopeBytes, aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Encrypt `plaintext` for the given `age` recipients.
    fn age_encrypt(&self, recipients: &[AgeRecipient], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt `ciphertext` using the given `age` identity.
    fn age_decrypt(&self, identity: &AgeIdentity, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Generate 32 cryptographically secure random bytes.
    fn random_bytes_32(&self) -> [u8; 32];

    /// Generate 24 cryptographically secure random bytes (XChaCha20 nonce size).
    fn random_bytes_24(&self) -> [u8; 24];

    /// Generate 16 cryptographically secure random bytes (Argon2id salt size).
    fn random_bytes_16(&self) -> [u8; 16];
}
