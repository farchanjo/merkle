//! OOB (Out-of-Band) Confirmation types.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ParseError;

/// The channel through which an OOB Confirmation challenge is delivered.
///
/// Sourced from `oob_channel` values in `reveal_request.cue`.
///
/// ```
/// use merkle_types::OobChannel;
///
/// let ch: OobChannel = "desktop-notif".parse().unwrap();
/// assert_eq!(ch, OobChannel::DesktopNotif);
/// assert_eq!(ch.to_string(), "desktop-notif");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OobChannel {
    /// Desktop notification delivered to the operator's primary display.
    #[serde(rename = "desktop-notif")]
    DesktopNotif,
    /// Terminal prompt rendered in the agent's controlling TTY.
    #[serde(rename = "terminal-prompt")]
    TerminalPrompt,
    /// Localhost confirmation page opened in the system browser.
    #[serde(rename = "localhost-confirm")]
    LocalhostConfirm,
}

impl fmt::Display for OobChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DesktopNotif => f.write_str("desktop-notif"),
            Self::TerminalPrompt => f.write_str("terminal-prompt"),
            Self::LocalhostConfirm => f.write_str("localhost-confirm"),
        }
    }
}

impl FromStr for OobChannel {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "desktop-notif" => Ok(Self::DesktopNotif),
            "terminal-prompt" => Ok(Self::TerminalPrompt),
            "localhost-confirm" => Ok(Self::LocalhostConfirm),
            other => Err(ParseError::UnknownOobChannel(other.to_owned())),
        }
    }
}

impl TryFrom<&str> for OobChannel {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for OobChannel {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

/// The outcome of an OOB Confirmation challenge.
///
/// Sourced from `#OobResolution.outcome` in `oob_resolution.cue`.
///
/// ```
/// use merkle_types::OobChallengeOutcome;
///
/// let o: OobChallengeOutcome = "approved".parse().unwrap();
/// assert_eq!(o, OobChallengeOutcome::Approved);
/// assert_eq!(o.to_string(), "approved");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OobChallengeOutcome {
    /// Operator confirmed the challenge.
    Approved,
    /// Operator explicitly rejected the challenge.
    Denied,
    /// TTL elapsed before the operator responded.
    Expired,
}

impl fmt::Display for OobChallengeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved => f.write_str("approved"),
            Self::Denied => f.write_str("denied"),
            Self::Expired => f.write_str("expired"),
        }
    }
}

impl FromStr for OobChallengeOutcome {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            "expired" => Ok(Self::Expired),
            other => Err(ParseError::UnknownOobChallengeOutcome(other.to_owned())),
        }
    }
}

impl TryFrom<&str> for OobChallengeOutcome {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for OobChallengeOutcome {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- OobChannel ---

    #[test]
    fn channel_all_variants_round_trip() {
        for (s, expected) in [
            ("desktop-notif", OobChannel::DesktopNotif),
            ("terminal-prompt", OobChannel::TerminalPrompt),
            ("localhost-confirm", OobChannel::LocalhostConfirm),
        ] {
            let parsed: OobChannel = s.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), s);
        }
    }

    #[test]
    fn channel_rejects_unknown() {
        assert!("sms".parse::<OobChannel>().is_err());
    }

    #[test]
    fn channel_serde_json_round_trip() {
        for c in [
            OobChannel::DesktopNotif,
            OobChannel::TerminalPrompt,
            OobChannel::LocalhostConfirm,
        ] {
            let json = serde_json::to_string(&c).unwrap();
            let parsed: OobChannel = serde_json::from_str(&json).unwrap();
            assert_eq!(c, parsed);
        }
    }

    // --- OobChallengeOutcome ---

    #[test]
    fn outcome_all_variants_round_trip() {
        for (s, expected) in [
            ("approved", OobChallengeOutcome::Approved),
            ("denied", OobChallengeOutcome::Denied),
            ("expired", OobChallengeOutcome::Expired),
        ] {
            let parsed: OobChallengeOutcome = s.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), s);
        }
    }

    #[test]
    fn outcome_rejects_unknown() {
        assert!("timeout".parse::<OobChallengeOutcome>().is_err());
    }

    #[test]
    fn outcome_serde_json_round_trip() {
        for o in [
            OobChallengeOutcome::Approved,
            OobChallengeOutcome::Denied,
            OobChallengeOutcome::Expired,
        ] {
            let json = serde_json::to_string(&o).unwrap();
            let parsed: OobChallengeOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(o, parsed);
        }
    }
}
