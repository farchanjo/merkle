//! `EciesEnvelope` — ECIES encrypted payload per ADR-0019.

use serde::{Deserialize, Serialize};

/// An ECIES-encrypted envelope delivered alongside an `OobChallenge`.
///
/// The construction is X25519 + XChaCha20-Poly1305 with BLAKE3-KDF, per
/// [ADR-0019](../../../docs/arch/adr/0019-ecies-encryption-for-oob-challenge-payload.md).
///
/// Only the enrolled Companion Device — which holds the corresponding X25519
/// private key — can decrypt the inner payload.  All other Companion Socket
/// subscribers receive opaque ciphertext bytes.
///
/// The `challenge_id` is bound as AEAD associated data, preventing ciphertext
/// transplantation across challenges.
///
/// # Fields
///
/// - `ephemeral_pubkey`: 32-byte X25519 public key generated ephemerally by
///   the Vault Agent for this specific challenge.
/// - `nonce`: 24-byte XChaCha20-Poly1305 nonce, drawn from `OsRng`.
/// - `ciphertext`: the encrypted inner payload (serialized `OobChallenge`
///   inner fields including `secret_handle`, `sensitivity`, `namespace_id`,
///   and `request_nonce`).
/// - `aead_tag`: 16-byte Poly1305 authentication tag.
///
/// ```
/// use merkle_domain_access_mediation::oob::ecies_envelope::EciesEnvelope;
///
/// let env = EciesEnvelope {
///     ephemeral_pubkey: [0u8; 32],
///     nonce: [0u8; 24],
///     ciphertext: vec![1, 2, 3],
///     aead_tag: [0u8; 16],
/// };
/// assert_eq!(env.ciphertext.len(), 3);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EciesEnvelope {
    /// 32-byte ephemeral X25519 public key (Curve25519 basepoint scalar mult).
    pub ephemeral_pubkey: [u8; 32],
    /// 24-byte XChaCha20-Poly1305 nonce drawn from `OsRng`.
    pub nonce: [u8; 24],
    /// Ciphertext bytes (serialized inner payload).
    pub ciphertext: Vec<u8>,
    /// 16-byte Poly1305 AEAD authentication tag.
    pub aead_tag: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_serde_json() {
        let env = EciesEnvelope {
            ephemeral_pubkey: [0xAA; 32],
            nonce: [0xBB; 24],
            ciphertext: vec![0x01, 0x02, 0x03],
            aead_tag: [0xCC; 16],
        };
        let json = serde_json::to_string(&env).expect("serialize");
        let back: EciesEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(env, back);
    }

    #[test]
    fn empty_ciphertext_is_valid() {
        let env = EciesEnvelope {
            ephemeral_pubkey: [0u8; 32],
            nonce: [0u8; 24],
            ciphertext: vec![],
            aead_tag: [0u8; 16],
        };
        assert!(env.ciphertext.is_empty());
    }
}
