//! ECIES construction per ADR-0019.
//!
//! ## Construction
//!
//! 1. Generate ephemeral X25519 keypair `(eph_secret, eph_public)` from `OsRng`.
//! 2. Compute shared secret `ss = X25519_DH(eph_secret, recipient_pk)` (32 bytes).
//! 3. Derive AEAD key: `key = BLAKE3_KDF(ss, context="merkle oob-challenge v1 encryption")`.
//!    Uses `blake3::derive_key` which hashes `context` into the key schedule.
//! 4. Generate a 24-byte nonce from `OsRng`.
//! 5. Encrypt with XChaCha20-Poly1305 (detached tag) binding `aad`.
//! 6. Return `EciesEnvelopeBytes { ephemeral_pubkey, nonce, ciphertext, aead_tag }`.
//!
//! Decryption is the exact reverse.

use merkle_ports::error::CryptoError;
use merkle_ports::{EciesEnvelopeBytes, X25519PrivateKey, X25519PublicKey};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::aead::{xchacha20_decrypt_detached, xchacha20_encrypt_detached};
use crate::rng::{random_24, random_32};

/// KDF context string mandated by ADR-0019 §ECIES Construction step 3.
const KDF_CONTEXT: &str = "merkle oob-challenge v1 encryption";

/// Encrypt `plaintext` for `recipient_pk` using ECIES (X25519 + BLAKE3 KDF +
/// XChaCha20-Poly1305).  `aad` is bound as AEAD associated data.
///
/// # Errors
///
/// Propagates [`CryptoError::AeadVerifyFailed`] on encryption failure (should
/// not occur in practice; included for API completeness).
pub(crate) fn encrypt(
    recipient_pk: &X25519PublicKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EciesEnvelopeBytes, CryptoError> {
    // Step 1: ephemeral keypair (names intentionally distinct to satisfy
    // clippy::similar_names: "eph_secret" vs "eph_pubkey").
    let eph_secret = StaticSecret::from(random_32());
    let eph_pubkey = PublicKey::from(&eph_secret);

    // Step 2: DH shared secret.
    let recipient_dh_pk = PublicKey::from(recipient_pk.0);
    let shared_secret = eph_secret.diffie_hellman(&recipient_dh_pk);

    // Step 3: BLAKE3 KDF.
    let aead_key: [u8; 32] = blake3::derive_key(KDF_CONTEXT, shared_secret.as_bytes());

    // Step 4: random nonce.
    let nonce = random_24();

    // Step 5: XChaCha20-Poly1305 encrypt (detached tag).
    let (ciphertext, aead_tag) = xchacha20_encrypt_detached(&aead_key, &nonce, plaintext, aad)?;

    Ok(EciesEnvelopeBytes {
        ephemeral_pubkey: eph_pubkey.to_bytes(),
        nonce,
        ciphertext,
        aead_tag,
    })
}

/// Decrypt an ECIES envelope using `recipient_sk`.
///
/// # Errors
///
/// Returns [`CryptoError::EciesDecryptFailed`] when the envelope's
/// authentication fails (wrong key, corrupted bytes, or AAD mismatch).
pub(crate) fn decrypt(
    recipient_sk: &X25519PrivateKey,
    envelope: &EciesEnvelopeBytes,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Reconstruct ephemeral public key and recipient secret.
    let sk = StaticSecret::from(recipient_sk.0);
    let eph_pubkey = PublicKey::from(envelope.ephemeral_pubkey);

    // Shared secret (mirrors encrypt step 2).
    let shared_secret = sk.diffie_hellman(&eph_pubkey);

    // BLAKE3 KDF (mirrors encrypt step 3).
    let aead_key: [u8; 32] = blake3::derive_key(KDF_CONTEXT, shared_secret.as_bytes());

    // XChaCha20-Poly1305 decrypt.
    xchacha20_decrypt_detached(
        &aead_key,
        &envelope.nonce,
        &envelope.ciphertext,
        aad,
        &envelope.aead_tag,
    )
    .map_err(|_| CryptoError::EciesDecryptFailed)
}
