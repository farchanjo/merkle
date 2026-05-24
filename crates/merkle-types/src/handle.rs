//! `Handle` — opaque `vault://<ns>/<cat>/<name>` URI.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{CategoryName, NamespaceLabel, ParseError, SecretName};

/// Opaque URI identifying a Secret without exposing its plaintext material.
///
/// Format: `vault://<namespace-label>/<category>/<secret-name>`
///
/// A `Handle` is sufficient to invoke any Proxy Tool; it is insufficient to
/// reveal plaintext — that requires an explicit `vault.reveal` with operator
/// confirmation.
///
/// ```
/// use merkle_types::{Handle, CategoryName, NamespaceLabel, SecretName};
///
/// let h: Handle = "vault://my-project/ssh/prod-key".parse().unwrap();
/// assert_eq!(h.namespace().as_str(), "my-project");
/// assert_eq!(h.category().to_string(), "ssh");
/// assert_eq!(h.secret_name().as_str(), "prod-key");
/// assert_eq!(h.to_string(), "vault://my-project/ssh/prod-key");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Handle {
    namespace: NamespaceLabel,
    category: CategoryName,
    secret_name: SecretName,
}

impl Handle {
    /// Construct a `Handle` from validated components.
    #[must_use]
    pub fn new(namespace: NamespaceLabel, category: CategoryName, secret_name: SecretName) -> Self {
        Self {
            namespace,
            category,
            secret_name,
        }
    }

    /// Return the namespace label component.
    #[must_use]
    pub fn namespace(&self) -> &NamespaceLabel {
        &self.namespace
    }

    /// Return the category component.
    #[must_use]
    pub fn category(&self) -> &CategoryName {
        &self.category
    }

    /// Return the secret name component.
    #[must_use]
    pub fn secret_name(&self) -> &SecretName {
        &self.secret_name
    }

    /// Return a URL-encoded path suitable for the `handle_encoded` OpenAPI
    /// path parameter: `/<ns>/<cat>/<name>` with percent-encoding applied.
    #[must_use]
    pub fn as_url_path(&self) -> String {
        // Components are restricted to `[a-z0-9-]` so percent-encoding is
        // a no-op in practice; we encode anyway for correctness.
        format!(
            "/{}/{}/{}",
            percent_encode(self.namespace.as_str()),
            percent_encode(self.category.as_str()),
            percent_encode(self.secret_name.as_str()),
        )
    }
}

/// Minimal percent-encoder: encodes only characters outside `[A-Za-z0-9-._~]`.
///
/// Since all three Handle components are restricted to `[a-z0-9-]`, this
/// function is effectively a no-op for valid Handle values.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            other => {
                out.push('%');
                out.push(char::from_digit(u32::from(other >> 4), 16).unwrap_or('0'));
                out.push(char::from_digit(u32::from(other & 0x0F), 16).unwrap_or('0'));
            }
        }
    }
    out
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "vault://{}/{}/{}",
            self.namespace, self.category, self.secret_name
        )
    }
}

impl FromStr for Handle {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let path = s
            .strip_prefix("vault://")
            .ok_or_else(|| ParseError::InvalidHandle(s.to_owned()))?;

        let parts: Vec<&str> = path.splitn(3, '/').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(ParseError::InvalidHandle(s.to_owned()));
        }

        let namespace = parts[0]
            .parse::<NamespaceLabel>()
            .map_err(|_| ParseError::InvalidHandle(format!("invalid namespace: {}", parts[0])))?;

        let category = parts[1]
            .parse::<CategoryName>()
            .map_err(|_| ParseError::InvalidHandle(format!("invalid category: {}", parts[1])))?;

        let secret_name = parts[2]
            .parse::<SecretName>()
            .map_err(|_| ParseError::InvalidHandle(format!("invalid secret name: {}", parts[2])))?;

        Ok(Self {
            namespace,
            category,
            secret_name,
        })
    }
}

impl TryFrom<&str> for Handle {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for Handle {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

impl Serialize for Handle {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Handle {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "vault://my-project/ssh/prod-key";

    #[test]
    fn round_trip_display_fromstr() {
        let h: Handle = VALID.parse().unwrap();
        assert_eq!(h.to_string(), VALID);
    }

    #[test]
    fn components_are_accessible() {
        let h: Handle = VALID.parse().unwrap();
        assert_eq!(h.namespace().as_str(), "my-project");
        assert_eq!(h.category().to_string(), "ssh");
        assert_eq!(h.secret_name().as_str(), "prod-key");
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!("http://my-project/ssh/key".parse::<Handle>().is_err());
    }

    #[test]
    fn rejects_missing_segments() {
        assert!("vault://my-project/ssh".parse::<Handle>().is_err());
        assert!("vault://my-project".parse::<Handle>().is_err());
    }

    #[test]
    fn rejects_empty_segments() {
        assert!("vault:///ssh/key".parse::<Handle>().is_err());
    }

    #[test]
    fn rejects_invalid_namespace() {
        assert!("vault://BAD/ssh/key".parse::<Handle>().is_err());
    }

    #[test]
    fn as_url_path() {
        let h: Handle = VALID.parse().unwrap();
        assert_eq!(h.as_url_path(), "/my-project/ssh/prod-key");
    }

    #[test]
    fn serde_json_round_trip() {
        let h: Handle = VALID.parse().unwrap();
        let json = serde_json::to_string(&h).unwrap();
        let parsed: Handle = serde_json::from_str(&json).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn custom_category_in_handle() {
        let h: Handle = "vault://my-project/my-custom/my-secret-1".parse().unwrap();
        assert!(matches!(h.category(), CategoryName::Custom(_)));
    }
}
