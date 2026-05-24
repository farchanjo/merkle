//! `TagKey`, `TagValue`, and `Tag` — structured Secret discriminators.

use std::fmt;
use std::str::FromStr;

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::ParseError;

/// Pattern for a `TagValue` slug.
///
/// `^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$` — allows single-char values only
/// if they are a lone lowercase letter or digit (the last group would not
/// match for len=1). For length=1, we accept any single `[a-z0-9]` char.
/// For length=2, `[a-z0-9][a-z0-9]` (no hyphen allowed in position 2 per CUE).
///
/// The CUE pattern is `^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$` which requires at
/// least 2 chars. We accept 1-char values separately for usability (single-char
/// env names like "a" are valid).
static TAG_VALUE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]([a-z0-9\-]{0,62}[a-z0-9])?$").expect("valid regex"));

// ---------------------------------------------------------------------------
// TagKey
// ---------------------------------------------------------------------------

/// The closed set of allowed tag discriminator keys.
///
/// Extending this enum requires a new ADR entry. The enum is closed
/// (no `#[non_exhaustive]`) because tag keys are a fixed policy domain.
///
/// ```
/// use merkle_types::TagKey;
/// use std::str::FromStr;
///
/// let key: TagKey = "env".parse().unwrap();
/// assert_eq!(key, TagKey::Env);
/// assert_eq!(key.to_string(), "env");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TagKey {
    /// Environment discriminator (e.g. `env:prod`).
    #[serde(rename = "env")]
    Env,
    /// Project discriminator (e.g. `project:acme`).
    #[serde(rename = "project")]
    Project,
    /// Role discriminator (e.g. `role:bastion`).
    #[serde(rename = "role")]
    Role,
    /// Cloud/infra provider (e.g. `provider:aws`).
    #[serde(rename = "provider")]
    Provider,
    /// Team discriminator (e.g. `team:sre`).
    #[serde(rename = "team")]
    Team,
}

impl fmt::Display for TagKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env => f.write_str("env"),
            Self::Project => f.write_str("project"),
            Self::Role => f.write_str("role"),
            Self::Provider => f.write_str("provider"),
            Self::Team => f.write_str("team"),
        }
    }
}

impl FromStr for TagKey {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "env" => Ok(Self::Env),
            "project" => Ok(Self::Project),
            "role" => Ok(Self::Role),
            "provider" => Ok(Self::Provider),
            "team" => Ok(Self::Team),
            other => Err(ParseError::InvalidTagKey(other.to_owned())),
        }
    }
}

impl TryFrom<&str> for TagKey {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

// ---------------------------------------------------------------------------
// TagValue
// ---------------------------------------------------------------------------

/// A validated slug for the value component of a `Tag`.
///
/// Pattern: `^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$` — single char allowed,
/// max 64 chars total.
///
/// ```
/// use merkle_types::TagValue;
///
/// let v: TagValue = "prod".parse().unwrap();
/// assert_eq!(v.as_str(), "prod");
///
/// // Single-char value is valid.
/// let single: TagValue = "a".parse().unwrap();
/// assert_eq!(single.as_str(), "a");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TagValue(String);

impl TagValue {
    /// Return the inner string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TagValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for TagValue {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if TAG_VALUE_RE.is_match(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(ParseError::InvalidTagValue(s.to_owned()))
        }
    }
}

impl TryFrom<&str> for TagValue {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for TagValue {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

impl Serialize for TagValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TagValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Tag
// ---------------------------------------------------------------------------

/// A structured `key:value` discriminator attached to a Secret.
///
/// Used for informal cohesion and cross-env auditing. `Tag` implements
/// `PartialEq`, `Eq`, and `Hash` so it can be stored in sets and maps.
///
/// ```
/// use merkle_types::{Tag, TagKey, TagValue};
///
/// let tag = Tag {
///     key: TagKey::Env,
///     value: "prod".parse().unwrap(),
/// };
/// assert_eq!(tag.to_string(), "env:prod");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tag {
    /// The tag key.
    pub key: TagKey,
    /// The validated slug value.
    pub value: TagValue,
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.key, self.value)
    }
}

impl FromStr for Tag {
    type Err = ParseError;

    /// Parse the canonical `key:value` pair string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (key_str, value_str) = s
            .split_once(':')
            .ok_or_else(|| ParseError::InvalidTagKey(s.to_owned()))?;

        let key = key_str.parse::<TagKey>()?;
        let value = value_str.parse::<TagValue>()?;
        Ok(Self { key, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- TagKey ---

    #[test]
    fn tag_key_all_variants_round_trip() {
        let cases = [
            ("env", TagKey::Env),
            ("project", TagKey::Project),
            ("role", TagKey::Role),
            ("provider", TagKey::Provider),
            ("team", TagKey::Team),
        ];
        for (s, expected) in cases {
            let parsed: TagKey = s.parse().unwrap();
            assert_eq!(parsed, expected, "key={s}");
            assert_eq!(parsed.to_string(), s, "display key={s}");
        }
    }

    #[test]
    fn tag_key_rejects_unknown() {
        assert!("unknown".parse::<TagKey>().is_err());
    }

    // --- TagValue ---

    #[test]
    fn tag_value_valid_slugs() {
        for v in ["prod", "a", "my-value", "abc123", "x1"] {
            let parsed: TagValue = v.parse().unwrap_or_else(|_| panic!("should parse: {v}"));
            assert_eq!(parsed.as_str(), v);
            assert_eq!(parsed.to_string(), v);
        }
    }

    #[test]
    fn tag_value_rejects_invalid() {
        for v in ["-leading", "Uppercase", "has space", ""] {
            assert!(v.parse::<TagValue>().is_err(), "should reject: {v:?}");
        }
    }

    #[test]
    fn tag_value_serde_round_trip() {
        let v: TagValue = "prod".parse().unwrap();
        let json = serde_json::to_string(&v).unwrap();
        let parsed: TagValue = serde_json::from_str(&json).unwrap();
        assert_eq!(v, parsed);
    }

    // --- Tag ---

    #[test]
    fn tag_display_and_fromstr() {
        let tag: Tag = "env:prod".parse().unwrap();
        assert_eq!(tag.key, TagKey::Env);
        assert_eq!(tag.value.as_str(), "prod");
        assert_eq!(tag.to_string(), "env:prod");
    }

    #[test]
    fn tag_serde_json_round_trip() {
        let tag = Tag {
            key: TagKey::Project,
            value: "acme".parse().unwrap(),
        };
        let json = serde_json::to_string(&tag).unwrap();
        let parsed: Tag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, parsed);
    }

    #[test]
    fn tag_rejects_unknown_key_in_pair() {
        assert!("unknown:value".parse::<Tag>().is_err());
    }
}
