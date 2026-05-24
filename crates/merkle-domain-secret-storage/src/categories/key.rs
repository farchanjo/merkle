//! `KeyCategory` — public metadata for `category = "key"` Secrets.

use serde::{Deserialize, Serialize};

/// Cryptographic key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    /// RSA key pair.
    Rsa,
    /// Ed25519 key pair.
    Ed25519,
    /// X25519 key pair (Diffie-Hellman).
    X25519,
    /// Symmetric key.
    Symmetric,
    /// secp256k1 key pair (Bitcoin/Ethereum).
    Secp256k1,
    /// Ed448 key pair.
    Ed448,
    /// age encryption key.
    Age,
}

/// Intended purpose of the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyPurpose {
    /// Digital signatures.
    Signing,
    /// Asymmetric encryption.
    Encryption,
    /// Key derivation function.
    Kdf,
    /// HMAC authentication.
    Hmac,
    /// age file encryption.
    Age,
    /// JWT signing.
    Jwt,
}

/// Public metadata fields for a `key` category Secret.
///
/// Maps the `#PublicMeta` shape from
/// `docs/arch/schemas/secret_storage/categories/key/key.cue`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCategory {
    /// Key type.
    pub key_kind: KeyKind,

    /// Intended purpose.
    pub purpose: KeyPurpose,

    /// Algorithm identifier string.
    pub algo: String,

    /// Public key bytes (base64 or raw), if the key has a public component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Vec<u8>>,

    /// Key fingerprint (algorithm-specific format).
    pub fingerprint: String,

    /// Key size in bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,

    /// Tool or library used to generate the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_with: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip() {
        let cat = KeyCategory {
            key_kind: KeyKind::Ed25519,
            purpose: KeyPurpose::Signing,
            algo: "Ed25519".into(),
            public_key: None,
            fingerprint: "SHA256:abc123".into(),
            bits: Some(256),
            created_with: Some("ssh-keygen".into()),
        };
        let json = serde_json::to_string(&cat).expect("serialize");
        let parsed: KeyCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cat, parsed);
    }
}
