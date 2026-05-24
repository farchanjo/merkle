//! # merkle-adapter-crypto
//!
//! **Driven-port adapter** — cryptographic primitives.
//! See `docs/arch/glossary.md#crypto-adapter` for the canonical description.
//!
//! ## Algorithms implemented
//!
//! Implements `CryptoPort` from `merkle-ports` using:
//!
//! - **XChaCha20-Poly1305** (RFC 8439 extended-nonce variant) — per-blob AEAD
//!   encryption; 24-byte nonces eliminate collision risk under heavy use.
//! - **BLAKE3** — Hash Chain content hashing:
//!   `current_hash = BLAKE3(canonical_content || prev_hash)`.
//!   Also used in keyed-derivation mode for the VaultHmacKey:
//!   `vault_hmac_key = BLAKE3(key=vault_root_key, data="merkle:vault-hmac-key:v1")`.
//! - **Argon2id** (RFC 9106) — MasterKey derivation from passphrase.
//!   Minimum Hardness Floor enforced at compile time:
//!   `m_cost >= 65536 KiB`, `t_cost >= 3`, `p_cost >= 1`.
//! - **age** — Backup encryption with two recipients (MasterKey public +
//!   RecoveryPublicKey). Filename: `merkle-bk-<utc-iso8601>.merkle.age`.
//! - **Ed25519** (`ed25519-dalek`) — Companion Device OobResolution signature
//!   verification; Operator Attestation JWT signing.
//! - **X25519** (`x25519-dalek`) — ECIES for OOB challenge payload encryption.
//! - Nonce generation via `OsRng`.
//!
//! ## Driving ports (inbound)
//!
//! None — driven adapter; called by multiple domain crates.
//!
//! ## Driven ports (outbound)
//!
//! Implements `merkle_ports::Crypto`.
//!
//! ## Cross-context relationships
//!
//! Consumed by IdentityAndSealing, SecretStorage, AuditCompliance, and
//! BackupRecovery bounded contexts.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod aead;
mod age_format;
mod argon2id;
mod blake3_hash;
mod ecies;
mod ed25519;
mod rng;
mod x25519_keys;

use merkle_domain_identity::Argon2idParams;
use merkle_ports::{
    AgeIdentity, AgeRecipient, EciesEnvelopeBytes, Ed25519PrivateKey, Ed25519PublicKey,
    X25519PrivateKey, X25519PublicKey,
};
use merkle_ports::error::CryptoError;
use merkle_types::{Blake3Hash, HmacSignature};
use thiserror::Error;

// Re-export entropy gate for use by application bootstrap.
pub use rng::assert_entropy_gate;

/// Internal error type for adapter-level failures (not part of the port API).
#[derive(Debug, Error)]
pub enum CryptoAdapterError {
    /// The OS entropy pool is below the minimum required threshold (Linux only).
    #[error("ENTROPY_UNAVAILABLE: {0}")]
    EntropyUnavailable(String),
}

/// `RustCryptoAdapter` implements [`merkle_ports::Crypto`] using the
/// RustCrypto ecosystem:
///
/// - `chacha20poly1305::XChaCha20Poly1305` for AEAD
/// - `blake3` for hashing and keyed MACs
/// - `ed25519-dalek` for signing/verification
/// - `x25519-dalek` + BLAKE3 KDF + XChaCha20Poly1305 for ECIES
/// - `argon2` for passphrase-based key derivation
/// - `age` for backup encryption
/// - `rand::rngs::OsRng` for all randomness
///
/// # Example
///
/// ```rust
/// use merkle_adapter_crypto::RustCryptoAdapter;
/// use merkle_ports::Crypto;
///
/// let adapter = RustCryptoAdapter::new();
/// let nonce = adapter.random_bytes_24();
/// assert_eq!(nonce.len(), 24);
/// ```
#[derive(Debug, Clone, Default)]
pub struct RustCryptoAdapter;

impl RustCryptoAdapter {
    /// Construct a new `RustCryptoAdapter`.
    ///
    /// This is a zero-cost constructor; no state is allocated.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl merkle_ports::Crypto for RustCryptoAdapter {
    /// Encrypt `plaintext` with XChaCha20-Poly1305.
    ///
    /// Returns `ciphertext || 16-byte Poly1305 tag`.
    fn aead_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        aead::xchacha20_encrypt(key, nonce, plaintext, aad)
    }

    /// Decrypt a `ciphertext || tag` blob produced by [`Self::aead_encrypt`].
    fn aead_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        aead::xchacha20_decrypt(key, nonce, ciphertext, aad)
    }

    /// Compute the BLAKE3 hash of `data`.
    fn blake3_hash(&self, data: &[u8]) -> Blake3Hash {
        blake3_hash::hash(data)
    }

    /// Compute a BLAKE3 keyed MAC (HMAC substitute) over `data`.
    fn blake3_keyed(&self, key: &[u8; 32], data: &[u8]) -> HmacSignature {
        blake3_hash::keyed(key, data)
    }

    /// Derive a 32-byte key from `passphrase` and `salt` using Argon2id.
    fn argon2id_derive(
        &self,
        passphrase: &[u8],
        salt: &[u8; 16],
        params: &Argon2idParams,
    ) -> Result<[u8; 32], CryptoError> {
        argon2id::derive(passphrase, salt, params)
    }

    /// Generate a fresh Ed25519 key pair.
    fn ed25519_keypair(&self) -> (Ed25519PrivateKey, Ed25519PublicKey) {
        ed25519::keypair()
    }

    /// Sign `msg` with `sk` and return the 64-byte detached signature.
    fn ed25519_sign(&self, sk: &Ed25519PrivateKey, msg: &[u8]) -> [u8; 64] {
        ed25519::sign(sk, msg)
    }

    /// Verify an Ed25519 signature.
    fn ed25519_verify(
        &self,
        pk: &Ed25519PublicKey,
        msg: &[u8],
        sig: &[u8; 64],
    ) -> Result<(), CryptoError> {
        ed25519::verify(pk, msg, sig)
    }

    /// Generate a fresh X25519 key pair.
    fn x25519_keypair(&self) -> (X25519PrivateKey, X25519PublicKey) {
        x25519_keys::keypair()
    }

    /// Encrypt `plaintext` for `recipient_pk` using ECIES (ADR-0019).
    fn x25519_ecies_encrypt(
        &self,
        recipient_pk: &X25519PublicKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<EciesEnvelopeBytes, CryptoError> {
        ecies::encrypt(recipient_pk, plaintext, aad)
    }

    /// Decrypt an ECIES envelope using `recipient_sk`.
    fn x25519_ecies_decrypt(
        &self,
        recipient_sk: &X25519PrivateKey,
        envelope: &EciesEnvelopeBytes,
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        ecies::decrypt(recipient_sk, envelope, aad)
    }

    /// Encrypt `plaintext` for `recipients` using the age v1 format.
    fn age_encrypt(
        &self,
        recipients: &[AgeRecipient],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        age_format::encrypt(recipients, plaintext)
    }

    /// Decrypt age ciphertext using `identity`.
    fn age_decrypt(
        &self,
        identity: &AgeIdentity,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        age_format::decrypt(identity, ciphertext)
    }

    /// Return 32 cryptographically secure random bytes.
    fn random_bytes_32(&self) -> [u8; 32] {
        rng::random_32()
    }

    /// Return 24 cryptographically secure random bytes.
    fn random_bytes_24(&self) -> [u8; 24] {
        rng::random_24()
    }

    /// Return 16 cryptographically secure random bytes.
    fn random_bytes_16(&self) -> [u8; 16] {
        rng::random_16()
    }
}
