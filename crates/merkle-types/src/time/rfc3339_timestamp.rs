//! `Rfc3339Timestamp` — RFC 3339 UTC timestamp newtype.

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::ParseError;

/// A UTC timestamp serialized as an RFC 3339 string.
///
/// Accepts both `Z` and `+00:00` timezone designators on parse; always
/// serializes with `Z` suffix.
///
/// ```
/// use merkle_types::Rfc3339Timestamp;
///
/// let ts = Rfc3339Timestamp::now();
/// let s = ts.to_string();
/// let parsed: Rfc3339Timestamp = s.parse().unwrap();
/// assert_eq!(ts, parsed);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Rfc3339Timestamp(DateTime<Utc>);

impl Rfc3339Timestamp {
    /// Return the current UTC time as an `Rfc3339Timestamp`.
    #[must_use]
    pub fn now() -> Self {
        Self(Utc::now())
    }

    /// Return the inner [`DateTime<Utc>`].
    #[must_use]
    pub fn inner(&self) -> DateTime<Utc> {
        self.0
    }
}

impl fmt::Display for Rfc3339Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Sub-second precision with Z suffix.
        // Use Micros to preserve the full precision stored in the inner
        // DateTime<Utc>, so that Display ↔ FromStr round-trips are lossless.
        write!(f, "{}", self.0.to_rfc3339_opts(SecondsFormat::Micros, true))
    }
}

impl FromStr for Rfc3339Timestamp {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DateTime::parse_from_rfc3339(s)
            .map(|dt| Self(dt.with_timezone(&Utc)))
            .map_err(|_| ParseError::InvalidRfc3339(s.to_owned()))
    }
}

impl TryFrom<&str> for Rfc3339Timestamp {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for Rfc3339Timestamp {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

impl Serialize for Rfc3339Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Rfc3339Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_display_fromstr() {
        let ts = Rfc3339Timestamp::now();
        let s = ts.to_string();
        let parsed: Rfc3339Timestamp = s.parse().unwrap();
        assert_eq!(ts, parsed);
    }

    #[test]
    fn accepts_z_suffix() {
        // Use microsecond precision so Display ↔ parse is lossless.
        let s = "2024-06-01T12:34:56.789000Z";
        let ts: Rfc3339Timestamp = s.parse().unwrap();
        assert_eq!(ts.to_string(), s);
    }

    #[test]
    fn accepts_offset_suffix() {
        let s = "2024-06-01T12:34:56+00:00";
        let ts: Rfc3339Timestamp = s.parse().unwrap();
        // Re-serialized as Z form with milliseconds
        assert!(ts.to_string().ends_with('Z'));
    }

    #[test]
    fn rejects_malformed() {
        assert!("not-a-timestamp".parse::<Rfc3339Timestamp>().is_err());
        assert!("2024-13-01T00:00:00Z".parse::<Rfc3339Timestamp>().is_err());
    }

    #[test]
    fn serde_json_round_trip() {
        let ts = Rfc3339Timestamp::now();
        let json = serde_json::to_string(&ts).unwrap();
        let parsed: Rfc3339Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(ts, parsed);
    }

    #[test]
    fn display_has_z_suffix() {
        let ts = Rfc3339Timestamp::now();
        assert!(ts.to_string().ends_with('Z'));
    }
}
