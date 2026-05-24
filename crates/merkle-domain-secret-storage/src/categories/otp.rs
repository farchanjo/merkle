//! `OtpCategory` — public metadata for `category = "otp"` Secrets.

use serde::{Deserialize, Serialize};

/// HMAC algorithm used by the OTP generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtpAlgo {
    /// HMAC-SHA1 (RFC 6238 default).
    SHA1,
    /// HMAC-SHA256.
    SHA256,
    /// HMAC-SHA512.
    SHA512,
}

/// Number of OTP digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OtpDigits {
    /// 6-digit OTP (most common).
    Six = 6,
    /// 8-digit OTP.
    Eight = 8,
}

/// Public metadata fields for an `otp` category Secret.
///
/// Maps the `#PublicMeta` shape from
/// `docs/arch/schemas/secret_storage/categories/otp/otp.cue`.
///
/// The TOTP seed lives in the encrypted `PrivateBlob`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtpCategory {
    /// Service name (e.g. `"GitHub"`).
    pub service: String,

    /// Account identifier (e.g. email or username).
    pub account: String,

    /// HMAC algorithm.
    pub algo: OtpAlgo,

    /// Number of OTP digits (6 or 8).
    pub digits: u8,

    /// TOTP time step in seconds (default 30).
    pub period: u32,

    /// Issuer label from the TOTP URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip() {
        let cat = OtpCategory {
            service: "github".into(),
            account: "user@example.com".into(),
            algo: OtpAlgo::SHA1,
            digits: 6,
            period: 30,
            issuer: Some("GitHub".into()),
        };
        let json = serde_json::to_string(&cat).expect("serialize");
        let parsed: OtpCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cat, parsed);
    }
}
