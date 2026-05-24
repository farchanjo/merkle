//! `CertCategory` — public metadata for `category = "cert"` Secrets.

use serde::{Deserialize, Serialize};

/// Extended key usage values for a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyUsage {
    /// TLS server authentication.
    ServerAuth,
    /// TLS client authentication.
    ClientAuth,
    /// Code signing.
    CodeSigning,
    /// Email protection (S/MIME).
    EmailProtection,
}

/// Key algorithm of the certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgo {
    /// RSA key.
    Rsa,
    /// Elliptic curve key.
    Ec,
    /// Ed25519 key.
    Ed25519,
}

/// Public metadata fields for a `cert` category Secret.
///
/// Maps the `#PublicMeta` shape from
/// `docs/arch/schemas/secret_storage/categories/cert/cert.cue`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertCategory {
    /// Common Name from the Subject field.
    pub subject_cn: String,

    /// Organization from the Subject field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_o: Option<String>,

    /// Common Name from the Issuer field.
    pub issuer_cn: String,

    /// Organization from the Issuer field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_o: Option<String>,

    /// Subject Alternative Names.
    pub san: Vec<String>,

    /// Certificate validity start (RFC 3339).
    pub not_before: String,

    /// Certificate validity end (RFC 3339).
    pub not_after: String,

    /// Serial number as colon-delimited hex.
    pub serial: String,

    /// SHA-256 fingerprint in `SHA256:<hex>` format.
    pub fingerprint_sha256: String,

    /// Public key algorithm.
    pub key_algo: KeyAlgo,

    /// Public key size in bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u32>,

    /// Chain certificates (PEM-encoded, public material only).
    pub chain_certs: Vec<String>,

    /// Extended key usage values.
    pub usage: Vec<KeyUsage>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip() {
        let cat = CertCategory {
            subject_cn: "example.com".into(),
            subject_o: None,
            issuer_cn: "Let's Encrypt".into(),
            issuer_o: None,
            san: vec!["example.com".into(), "www.example.com".into()],
            not_before: "2024-01-01T00:00:00Z".into(),
            not_after: "2025-01-01T00:00:00Z".into(),
            serial: "01:02:03".into(),
            fingerprint_sha256: "SHA256:abc123".into(),
            key_algo: KeyAlgo::Ec,
            key_bits: Some(256),
            chain_certs: vec![],
            usage: vec![KeyUsage::ServerAuth],
        };
        let json = serde_json::to_string(&cat).expect("serialize");
        let parsed: CertCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cat, parsed);
    }
}
