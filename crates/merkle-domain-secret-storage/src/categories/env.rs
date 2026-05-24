//! `EnvCategory` — public metadata for `category = "env"` Secrets.

use serde::{Deserialize, Serialize};

/// Serialization shape for the environment variable set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvShape {
    /// `.env` file format (KEY=VALUE lines).
    Dotenv,
    /// JSON object (`{"KEY": "VALUE"}`).
    Json,
    /// TOML key-value section.
    Toml,
}

/// Public metadata fields for an `env` category Secret.
///
/// Maps the `#PublicMeta` shape from
/// `docs/arch/schemas/secret_storage/categories/env/env.cue`.
///
/// The actual environment variable values live in the encrypted
/// `PrivateBlob`, never here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvCategory {
    /// Names of the environment variables (without their values).
    pub keys: Vec<String>,

    /// Profile name (e.g. `"production"`, `"staging"`).
    pub profile: String,

    /// Wire format for the env set.
    pub shape: EnvShape,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip() {
        let cat = EnvCategory {
            keys: vec!["DATABASE_URL".into(), "REDIS_URL".into()],
            profile: "production".into(),
            shape: EnvShape::Dotenv,
        };
        let json = serde_json::to_string(&cat).expect("serialize");
        let parsed: EnvCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cat, parsed);
    }
}
