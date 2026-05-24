//! `PasswordCategory` — public metadata for `category = "password"` Secrets.

use serde::{Deserialize, Serialize};

/// Public metadata fields for a `password` category Secret.
///
/// Maps the `#PublicMeta` shape from
/// `docs/arch/schemas/secret_storage/categories/password/password.cue`.
///
/// # Security
///
/// None of these fields contain the password value. The password, TOTP seed,
/// and OTP configuration live in the encrypted `PrivateBlob`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordCategory {
    /// Service URL where this password is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Username or login identifier.
    pub username: String,

    /// Human-readable service name (e.g. `"GitHub"`).
    pub service_name: String,

    /// Optional public commentary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes_public: Option<String>,

    /// Trailing four characters of the password for quick identification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last4_password: Option<String>,
}
