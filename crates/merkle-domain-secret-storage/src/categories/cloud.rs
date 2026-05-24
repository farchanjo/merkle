//! `CloudCategory` — public metadata for `category = "cloud"` Secrets.

use serde::{Deserialize, Serialize};

/// Supported cloud and hosting providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    /// Amazon Web Services.
    Aws,
    /// Google Cloud Platform.
    Gcp,
    /// Microsoft Azure.
    Azure,
    /// DigitalOcean.
    Do,
    /// Hetzner.
    Hetzner,
    /// Linode / Akamai.
    Linode,
    /// Vultr.
    Vultr,
    /// Oracle Cloud Infrastructure.
    Oci,
}

/// Public metadata fields for a `cloud` category Secret.
///
/// Maps the `#PublicMeta` shape from
/// `docs/arch/schemas/secret_storage/categories/cloud/cloud.cue`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudCategory {
    /// Cloud provider.
    pub provider: CloudProvider,

    /// Account or project ID.
    pub account_id: String,

    /// Default region (e.g. `"us-east-1"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_default: Option<String>,

    /// Named profile (e.g. AWS CLI profile name).
    pub profile: String,

    /// IAM role ARN to assume, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,

    /// Whether MFA is required to use this credential.
    pub mfa_required: bool,

    /// Non-secret portion of an access key pair (e.g. AWS Access Key ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id_public: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip() {
        let cat = CloudCategory {
            provider: CloudProvider::Aws,
            account_id: "123456789012".into(),
            region_default: Some("us-east-1".into()),
            profile: "prod".into(),
            role_arn: None,
            mfa_required: false,
            key_id_public: Some("AKIAIOSFODNN7EXAMPLE".into()),
        };
        let json = serde_json::to_string(&cat).expect("serialize");
        let parsed: CloudCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cat, parsed);
    }
}
