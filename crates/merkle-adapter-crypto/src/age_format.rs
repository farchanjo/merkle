//! age encrypt / decrypt helpers (ADR-0006).
//!
//! Recipients are Bech32 `age1...` strings (X25519 public keys).
//! Identities are Bech32 `AGE-SECRET-KEY-1...` strings (X25519 secret keys).

use std::io::{Read, Write};

use merkle_ports::error::CryptoError;
use merkle_ports::{AgeIdentity, AgeRecipient};

/// Encrypt `plaintext` for each `recipient` and return the binary age ciphertext.
///
/// # Errors
///
/// Returns [`CryptoError::Age`] when any recipient string fails to parse or
/// when the age encryption fails.
pub(crate) fn encrypt(
    recipients: &[AgeRecipient],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let boxed: Vec<Box<dyn age::Recipient + Send>> = recipients
        .iter()
        .map(|r| {
            r.0.parse::<age::x25519::Recipient>()
                .map(|rec| Box::new(rec) as Box<dyn age::Recipient + Send>)
                .map_err(|e| CryptoError::Age(format!("invalid recipient '{}': {e}", r.0)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let encryptor = age::Encryptor::with_recipients(boxed)
        .ok_or_else(|| CryptoError::Age("recipient list is empty".to_owned()))?;

    let mut output: Vec<u8> = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut output)
        .map_err(|e| CryptoError::Age(format!("wrap_output failed: {e}")))?;

    writer
        .write_all(plaintext)
        .map_err(|e| CryptoError::Age(format!("write failed: {e}")))?;

    writer
        .finish()
        .map_err(|e| CryptoError::Age(format!("finish failed: {e}")))?;

    Ok(output)
}

/// Decrypt age `ciphertext` using `identity` (`AGE-SECRET-KEY-1...` string).
///
/// # Errors
///
/// Returns [`CryptoError::Age`] on parse or decryption failures.
pub(crate) fn decrypt(identity: &AgeIdentity, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let id: age::x25519::Identity = identity
        .0
        .parse()
        .map_err(|e| CryptoError::Age(format!("invalid identity: {e}")))?;

    let decryptor = match age::Decryptor::new(ciphertext)
        .map_err(|e| CryptoError::Age(format!("decryptor creation failed: {e}")))?
    {
        age::Decryptor::Recipients(d) => d,
        age::Decryptor::Passphrase(_) => {
            return Err(CryptoError::Age(
                "expected recipient-based age file, got passphrase-based".to_owned(),
            ));
        }
    };

    let mut output = Vec::new();
    let mut reader = decryptor
        .decrypt(std::iter::once(&id as &dyn age::Identity))
        .map_err(|e| CryptoError::Age(format!("decrypt failed: {e}")))?;

    reader
        .read_to_end(&mut output)
        .map_err(|e| CryptoError::Age(format!("read failed: {e}")))?;

    Ok(output)
}
