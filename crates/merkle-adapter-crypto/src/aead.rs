//! XChaCha20-Poly1305 AEAD helpers (ADR-0004).
//!
//! All nonce and key lengths are validated at the type level via fixed-size
//! array parameters.  The ciphertext format is the raw XChaCha20-Poly1305
//! output (ciphertext bytes + 16-byte Poly1305 tag, concatenated by the
//! `chacha20poly1305` crate).

use chacha20poly1305::{
    AeadInPlace, Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::Aead,
};
use merkle_ports::error::CryptoError;

/// Encrypt `plaintext` with `key` and `nonce`, binding `aad` as associated
/// data.
///
/// Returns the raw ciphertext with the 16-byte Poly1305 tag appended.
pub(crate) fn xchacha20_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);

    // `encrypt_in_place_detached` is not used here because the ports trait
    // wants a single Vec<u8> containing ciphertext || tag.  We use the
    // higher-level `encrypt` API with a Payload to bind the AAD.
    let payload = chacha20poly1305::aead::Payload { msg: plaintext, aad };
    cipher
        .encrypt(xnonce, payload)
        .map_err(|_| CryptoError::AeadVerifyFailed)
}

/// Decrypt `ciphertext` (ciphertext || 16-byte tag) using `key`, `nonce`, and
/// `aad`.
///
/// Returns the plaintext on success.  Any authentication failure maps to
/// [`CryptoError::AeadVerifyFailed`].
pub(crate) fn xchacha20_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);

    let payload = chacha20poly1305::aead::Payload { msg: ciphertext, aad };
    cipher
        .decrypt(xnonce, payload)
        .map_err(|_| CryptoError::AeadVerifyFailed)
}

/// Encrypt returning separate ciphertext and tag buffers (used by ECIES).
///
/// Returns `(ciphertext_bytes, tag_16)`.
pub(crate) fn xchacha20_encrypt_detached(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);

    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(xnonce, aad, &mut buf)
        .map_err(|_| CryptoError::AeadVerifyFailed)?;

    let mut tag_bytes = [0u8; 16];
    tag_bytes.copy_from_slice(tag.as_slice());
    Ok((buf, tag_bytes))
}

/// Decrypt using separate ciphertext and tag buffers (used by ECIES).
pub(crate) fn xchacha20_decrypt_detached(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::aead::Tag;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);

    let mut buf = ciphertext.to_vec();
    let tag_ref = Tag::<XChaCha20Poly1305>::from_slice(tag);
    cipher
        .decrypt_in_place_detached(xnonce, aad, &mut buf, tag_ref)
        .map_err(|_| CryptoError::AeadVerifyFailed)?;
    Ok(buf)
}
