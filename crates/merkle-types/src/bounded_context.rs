//! `BoundedContextId` — identifies one of the six bounded contexts.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ParseError;

/// One of the six bounded contexts of the Merkle system.
///
/// Used as a discriminator in cross-context audit entries and context-map
/// tooling. Display form is kebab-case.
///
/// ```
/// use merkle_types::BoundedContextId;
///
/// let bc: BoundedContextId = "secret-storage".parse().unwrap();
/// assert_eq!(bc, BoundedContextId::SecretStorage);
/// assert_eq!(bc.to_string(), "secret-storage");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundedContextId {
    /// Identity and Sealing — key hierarchy, unseal protocol.
    #[serde(rename = "identity-and-sealing")]
    IdentityAndSealing,
    /// Secret Storage — namespaces, secrets, categories, tags.
    #[serde(rename = "secret-storage")]
    SecretStorage,
    /// Access Mediation — proxy tools, use tokens, OOB confirmation.
    #[serde(rename = "access-mediation")]
    AccessMediation,
    /// Audit and Compliance — append-only audit log, hash chain.
    #[serde(rename = "audit-compliance")]
    AuditCompliance,
    /// Backup and Recovery — encrypted backups, disaster recovery.
    #[serde(rename = "backup-recovery")]
    BackupRecovery,
    /// Policy and Permissions — namespace policies, security profiles.
    #[serde(rename = "policy-permissions")]
    PolicyPermissions,
}

impl fmt::Display for BoundedContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityAndSealing => f.write_str("identity-and-sealing"),
            Self::SecretStorage => f.write_str("secret-storage"),
            Self::AccessMediation => f.write_str("access-mediation"),
            Self::AuditCompliance => f.write_str("audit-compliance"),
            Self::BackupRecovery => f.write_str("backup-recovery"),
            Self::PolicyPermissions => f.write_str("policy-permissions"),
        }
    }
}

impl FromStr for BoundedContextId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "identity-and-sealing" => Ok(Self::IdentityAndSealing),
            "secret-storage" => Ok(Self::SecretStorage),
            "access-mediation" => Ok(Self::AccessMediation),
            "audit-compliance" => Ok(Self::AuditCompliance),
            "backup-recovery" => Ok(Self::BackupRecovery),
            "policy-permissions" => Ok(Self::PolicyPermissions),
            other => Err(ParseError::InvalidHandle(format!(
                "unknown bounded context: {other}"
            ))),
        }
    }
}

impl TryFrom<&str> for BoundedContextId {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<String> for BoundedContextId {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[(&str, BoundedContextId)] = &[
        ("identity-and-sealing", BoundedContextId::IdentityAndSealing),
        ("secret-storage", BoundedContextId::SecretStorage),
        ("access-mediation", BoundedContextId::AccessMediation),
        ("audit-compliance", BoundedContextId::AuditCompliance),
        ("backup-recovery", BoundedContextId::BackupRecovery),
        ("policy-permissions", BoundedContextId::PolicyPermissions),
    ];

    #[test]
    fn exactly_six_variants() {
        assert_eq!(ALL.len(), 6);
    }

    #[test]
    fn all_variants_round_trip() {
        for (s, expected) in ALL {
            let parsed: BoundedContextId = s.parse().unwrap();
            assert_eq!(&parsed, expected);
            assert_eq!(parsed.to_string(), *s);
        }
    }

    #[test]
    fn rejects_unknown() {
        assert!("data-platform".parse::<BoundedContextId>().is_err());
    }

    #[test]
    fn serde_json_round_trip() {
        for (_, bc) in ALL {
            let json = serde_json::to_string(bc).unwrap();
            let parsed: BoundedContextId = serde_json::from_str(&json).unwrap();
            assert_eq!(bc, &parsed);
        }
    }
}
