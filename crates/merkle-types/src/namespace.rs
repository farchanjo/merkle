//! `NamespaceLabel`, `CategoryName`, and `SecretName` value objects.

use std::fmt;
use std::str::FromStr;

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::ParseError;

// ---------------------------------------------------------------------------
// Shared regex patterns
// ---------------------------------------------------------------------------

/// DNS-subdomain-style slug: starts with a lowercase letter, ends with a
/// letter or digit, hyphens in the middle, total 3–63 characters.
///
/// Mirrors `#NamespaceLabel` from `docs/arch/schemas/secret_storage/handle.cue`.
static NS_LABEL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9\-]{1,61}[a-z0-9]$").expect("valid regex"));

/// Alternative cwd-bound form: `cwd-<16 hex digits>`.
static NS_CWD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^cwd-[0-9a-f]{16}$").expect("valid regex"));

/// Secret name slug: lowercase, 3–63 characters, same shape as `NS_LABEL_RE`.
static SECRET_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9\-]{1,61}[a-z0-9]$").expect("valid regex"));

/// Category slug (custom or display): `^[a-z][a-z0-9-]*$`
static CATEGORY_SLUG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9\-]*$").expect("valid regex"));

// ---------------------------------------------------------------------------
// NamespaceLabel
// ---------------------------------------------------------------------------

/// A validated DNS-subdomain-style label that identifies a Namespace.
///
/// Accepts two forms:
/// - Standard: `^[a-z][a-z0-9-]{1,61}[a-z0-9]$` (3–63 chars)
/// - CWD-bound: `^cwd-[0-9a-f]{16}$`
///
/// ```
/// use merkle_types::NamespaceLabel;
///
/// let label: NamespaceLabel = "my-project".parse().unwrap();
/// assert_eq!(label.as_str(), "my-project");
/// assert_eq!(label.to_string(), "my-project");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NamespaceLabel(String);

impl NamespaceLabel {
    /// Return the inner string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NamespaceLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NamespaceLabel {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if NS_LABEL_RE.is_match(s) || NS_CWD_RE.is_match(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(ParseError::InvalidNamespaceLabel(s.to_owned()))
        }
    }
}

impl TryFrom<&str> for NamespaceLabel {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for NamespaceLabel {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

impl Serialize for NamespaceLabel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NamespaceLabel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// CategoryName
// ---------------------------------------------------------------------------

/// A Secret category — either a built-in variant or a custom slug.
///
/// The eleven built-in categories are closed; `Custom(String)` handles any
/// valid slug that does not match a built-in name.
///
/// ```
/// use merkle_types::CategoryName;
///
/// let cat: CategoryName = "ssh".parse().unwrap();
/// assert_eq!(cat, CategoryName::SshKey);
/// assert_eq!(cat.to_string(), "ssh");
///
/// let custom: CategoryName = "my-custom".parse().unwrap();
/// assert!(matches!(custom, CategoryName::Custom(_)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CategoryName {
    /// Stored passwords.
    Password,
    /// TOTP/HOTP secrets.
    OtpSecret,
    /// SSH private keys.
    SshKey,
    /// GPG private keys.
    GpgKey,
    /// API tokens and bearer tokens.
    Token,
    /// TLS/PKI certificates (including private key).
    Cert,
    /// Cloud provider credentials (AWS, GCP, Azure, …).
    Cloud,
    /// Database connection strings and credentials.
    Database,
    /// Environment variable sets.
    Env,
    /// Unstructured notes.
    Note,
    /// Generic symmetric or asymmetric key material.
    Key,
    /// A custom user-defined category slug (lowercase, hyphens allowed).
    Custom(String),
}

impl CategoryName {
    /// Return the canonical lowercase display string for this category.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Password => "password",
            Self::OtpSecret => "otp",
            Self::SshKey => "ssh",
            Self::GpgKey => "gpg",
            Self::Token => "token",
            Self::Cert => "cert",
            Self::Cloud => "cloud",
            Self::Database => "database",
            Self::Env => "env",
            Self::Note => "note",
            Self::Key => "key",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for CategoryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CategoryName {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "password" => Ok(Self::Password),
            "otp" => Ok(Self::OtpSecret),
            "ssh" => Ok(Self::SshKey),
            "gpg" => Ok(Self::GpgKey),
            "token" => Ok(Self::Token),
            "cert" => Ok(Self::Cert),
            "cloud" => Ok(Self::Cloud),
            "database" => Ok(Self::Database),
            "env" => Ok(Self::Env),
            "note" => Ok(Self::Note),
            "key" => Ok(Self::Key),
            other => {
                if CATEGORY_SLUG_RE.is_match(other) {
                    Ok(Self::Custom(other.to_owned()))
                } else {
                    Err(ParseError::InvalidCategory(s.to_owned()))
                }
            }
        }
    }
}

impl TryFrom<&str> for CategoryName {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for CategoryName {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

impl Serialize for CategoryName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CategoryName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// SecretName
// ---------------------------------------------------------------------------

/// A validated slug identifying a secret within its namespace and category.
///
/// Pattern: `^[a-z][a-z0-9-]{1,61}[a-z0-9]$` (3–63 chars).
///
/// ```
/// use merkle_types::SecretName;
///
/// let name: SecretName = "my-api-key".parse().unwrap();
/// assert_eq!(name.as_str(), "my-api-key");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretName(String);

impl SecretName {
    /// Return the inner string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SecretName {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if SECRET_NAME_RE.is_match(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(ParseError::InvalidSecretName(s.to_owned()))
        }
    }
}

impl TryFrom<&str> for SecretName {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for SecretName {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

impl Serialize for SecretName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- NamespaceLabel ---

    #[test]
    fn namespace_label_valid_standard() {
        let label: NamespaceLabel = "my-project".parse().unwrap();
        assert_eq!(label.as_str(), "my-project");
        assert_eq!(label.to_string(), "my-project");
    }

    #[test]
    fn namespace_label_valid_cwd() {
        let cwd = "cwd-0123456789abcdef";
        let label: NamespaceLabel = cwd.parse().unwrap();
        assert_eq!(label.as_str(), cwd);
    }

    #[test]
    fn namespace_label_rejects_uppercase() {
        assert!("MyProject".parse::<NamespaceLabel>().is_err());
    }

    #[test]
    fn namespace_label_rejects_too_short() {
        // Two chars — below minimum of 3
        assert!("ab".parse::<NamespaceLabel>().is_err());
    }

    #[test]
    fn namespace_label_rejects_leading_hyphen() {
        assert!("-bad".parse::<NamespaceLabel>().is_err());
    }

    #[test]
    fn namespace_label_serde_round_trip() {
        let label: NamespaceLabel = "vault-prod".parse().unwrap();
        let json = serde_json::to_string(&label).unwrap();
        let parsed: NamespaceLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(label, parsed);
    }

    // --- CategoryName ---

    #[test]
    fn category_all_builtins_round_trip() {
        let cases = [
            ("password", CategoryName::Password),
            ("otp", CategoryName::OtpSecret),
            ("ssh", CategoryName::SshKey),
            ("gpg", CategoryName::GpgKey),
            ("token", CategoryName::Token),
            ("cert", CategoryName::Cert),
            ("cloud", CategoryName::Cloud),
            ("database", CategoryName::Database),
            ("env", CategoryName::Env),
            ("note", CategoryName::Note),
            ("key", CategoryName::Key),
        ];
        for (slug, expected) in cases {
            let parsed: CategoryName = slug.parse().unwrap();
            assert_eq!(parsed, expected, "slug={slug}");
            assert_eq!(parsed.to_string(), slug, "display slug={slug}");
        }
    }

    #[test]
    fn category_custom_valid_slug() {
        let cat: CategoryName = "my-custom-type".parse().unwrap();
        assert!(matches!(cat, CategoryName::Custom(_)));
        assert_eq!(cat.to_string(), "my-custom-type");
    }

    #[test]
    fn category_rejects_invalid_slug() {
        assert!("Bad-Category".parse::<CategoryName>().is_err());
        assert!("-leading-hyphen".parse::<CategoryName>().is_err());
    }

    #[test]
    fn category_serde_round_trip() {
        let cat: CategoryName = "ssh".parse().unwrap();
        let json = serde_json::to_string(&cat).unwrap();
        let parsed: CategoryName = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, parsed);
    }

    // --- SecretName ---

    #[test]
    fn secret_name_valid() {
        let name: SecretName = "prod-api-key".parse().unwrap();
        assert_eq!(name.as_str(), "prod-api-key");
        assert_eq!(name.to_string(), "prod-api-key");
    }

    #[test]
    fn secret_name_rejects_uppercase() {
        assert!("MySecret".parse::<SecretName>().is_err());
    }

    #[test]
    fn secret_name_serde_round_trip() {
        let name: SecretName = "my-secret".parse().unwrap();
        let json = serde_json::to_string(&name).unwrap();
        let parsed: SecretName = serde_json::from_str(&json).unwrap();
        assert_eq!(name, parsed);
    }
}
