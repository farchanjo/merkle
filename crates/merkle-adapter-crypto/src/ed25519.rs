//! Ed25519 key-pair generation, signing, and verification (ADR-0011 / ADR-0019).
//!
//! Uses `ed25519-dalek` with `rand_core::OsRng` (0.6 family) for key
//! generation.  All signing and verification is deterministic once the key is
//! fixed.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use merkle_ports::{Ed25519PrivateKey, Ed25519PublicKey};
use merkle_ports::error::CryptoError;
use rand_core::OsRng;

/// Generate a fresh Ed25519 signing key pair using `rand_core::OsRng`.
pub(crate) fn keypair() -> (Ed25519PrivateKey, Ed25519PublicKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (
        Ed25519PrivateKey(signing_key.to_bytes()),
        Ed25519PublicKey(verifying_key.to_bytes()),
    )
}

/// Sign `msg` with `sk` and return the 64-byte signature.
pub(crate) fn sign(sk: &Ed25519PrivateKey, msg: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(&sk.0);
    let signature: Signature = signing_key.sign(msg);
    signature.to_bytes()
}

/// Verify `sig` over `msg` with `pk`.
///
/// # Errors
///
/// Returns [`CryptoError::SignatureVerifyFailed`] on any verification failure.
pub(crate) fn verify(
    pk: &Ed25519PublicKey,
    msg: &[u8],
    sig: &[u8; 64],
) -> Result<(), CryptoError> {
    let verifying_key = VerifyingKey::from_bytes(&pk.0)
        .map_err(|_| CryptoError::SignatureVerifyFailed)?;
    let signature = Signature::from_bytes(sig);
    verifying_key
        .verify(msg, &signature)
        .map_err(|_| CryptoError::SignatureVerifyFailed)
}
