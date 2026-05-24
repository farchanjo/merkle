//! Per-category public metadata payload types.
//!
//! Each variant of [`CategoryPayload`] mirrors its corresponding CUE schema
//! under `docs/arch/schemas/secret_storage/categories/`. The `Custom` variant
//! holds an arbitrary JSON value for user-defined schemas.

pub mod cert;
pub mod cloud;
pub mod database;
pub mod env;
pub mod gpg_key;
pub mod key;
pub mod note;
pub mod otp;
pub mod password;
pub mod ssh_key;
pub mod token;

pub use cert::CertCategory;
pub use cloud::CloudCategory;
pub use database::DatabaseCategory;
pub use env::EnvCategory;
pub use gpg_key::GpgKeyCategory;
pub use key::KeyCategory;
pub use note::NoteCategory;
pub use otp::OtpCategory;
pub use password::PasswordCategory;
pub use ssh_key::SshKeyCategory;
pub use token::TokenCategory;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Discriminated union of all per-category public metadata payloads.
///
/// The `category` serde tag matches the CUE `#CategoryName` discriminator.
/// `Custom` holds raw JSON for user-defined categories not covered by the
/// built-in set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "category", rename_all = "lowercase")]
pub enum CategoryPayload {
    /// `password` category payload.
    Password(PasswordCategory),
    /// `ssh` category payload.
    Ssh(SshKeyCategory),
    /// `gpg` category payload.
    Gpg(GpgKeyCategory),
    /// `token` category payload.
    Token(TokenCategory),
    /// `cert` category payload.
    Cert(CertCategory),
    /// `cloud` category payload.
    Cloud(CloudCategory),
    /// `database` category payload.
    Database(DatabaseCategory),
    /// `env` category payload.
    Env(EnvCategory),
    /// `key` category payload.
    Key(KeyCategory),
    /// `note` category payload.
    Note(NoteCategory),
    /// `otp` category payload.
    Otp(OtpCategory),
    /// User-defined category; the payload is an arbitrary JSON object.
    ///
    /// Serialized as `"category": "custom"`. Use
    /// [`CategoryPayload::from_custom_json`] to construct.
    #[serde(rename = "custom")]
    Custom(Value),
}

impl CategoryPayload {
    /// Construct a `Custom` payload from any [`serde_json::Value`].
    #[must_use]
    pub fn from_custom_json(value: Value) -> Self {
        Self::Custom(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::categories::token::TokenType;

    #[test]
    fn token_payload_round_trip() {
        let payload = CategoryPayload::Token(TokenCategory {
            service: "github".into(),
            token_type: TokenType::Bearer,
            header_name: "Authorization".into(),
            scope: vec!["repo".into()],
            expires_at: None,
            revocation_url: None,
            prefix: None,
        });
        let json = serde_json::to_string(&payload).expect("serialize");
        let parsed: CategoryPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(payload, parsed);
    }

    #[test]
    fn custom_payload_constructed() {
        let v = serde_json::json!({"key": "value"});
        let payload = CategoryPayload::from_custom_json(v.clone());
        assert!(matches!(payload, CategoryPayload::Custom(_)));
        let json = serde_json::to_string(&payload).expect("serialize");
        assert!(json.contains("custom"));
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one assert per built-in category variant"
    )]
    fn all_builtin_variants_serialize() {
        use crate::categories::{
            cert::{CertCategory, KeyAlgo},
            cloud::{CloudCategory, CloudProvider},
            database::{DatabaseCategory, DbEngine, ReplicaRole, SslMode},
            env::{EnvCategory, EnvShape},
            gpg_key::{GpgAlgo, GpgKeyCategory},
            key::{KeyCategory, KeyKind, KeyPurpose},
            note::{NoteCategory, NoteContentType},
            otp::{OtpAlgo, OtpCategory},
            password::PasswordCategory,
            ssh_key::{SshAuthMethod, SshKeyCategory},
        };

        let cases: Vec<CategoryPayload> = vec![
            CategoryPayload::Password(PasswordCategory {
                url: None,
                username: "user".into(),
                service_name: "Service".into(),
                notes_public: None,
                last4_password: None,
            }),
            CategoryPayload::Ssh(SshKeyCategory {
                host: "host".into(),
                port: 22,
                user: "admin".into(),
                auth_method: SshAuthMethod::Key,
                key_type: None,
                fingerprint: "SHA256:abc".into(),
                key_bits: None,
                known_hosts_fp: None,
                jump_host_handle: None,
                proxy_command: None,
            }),
            CategoryPayload::Gpg(GpgKeyCategory {
                key_id: "ABCDEF0123456789".into(),
                fingerprint: "A".repeat(40),
                uid: vec!["Test User <test@example.com>".into()],
                algo: GpgAlgo::Ed25519,
                created: "2024-01-01T00:00:00Z".into(),
                expires: None,
                subkeys: vec![],
            }),
            CategoryPayload::Token(TokenCategory {
                service: "svc".into(),
                token_type: crate::categories::token::TokenType::Bearer,
                header_name: "Authorization".into(),
                scope: vec![],
                expires_at: None,
                revocation_url: None,
                prefix: None,
            }),
            CategoryPayload::Cert(CertCategory {
                subject_cn: "example.com".into(),
                subject_o: None,
                issuer_cn: "CA".into(),
                issuer_o: None,
                san: vec![],
                not_before: "2024-01-01T00:00:00Z".into(),
                not_after: "2025-01-01T00:00:00Z".into(),
                serial: "01".into(),
                fingerprint_sha256: "SHA256:abc".into(),
                key_algo: KeyAlgo::Ec,
                key_bits: None,
                chain_certs: vec![],
                usage: vec![],
            }),
            CategoryPayload::Cloud(CloudCategory {
                provider: CloudProvider::Aws,
                account_id: "123".into(),
                region_default: None,
                profile: "prod".into(),
                role_arn: None,
                mfa_required: false,
                key_id_public: None,
            }),
            CategoryPayload::Database(DatabaseCategory {
                engine: DbEngine::Postgres,
                host: "db".into(),
                port: 5432,
                database: "app".into(),
                user: "u".into(),
                ssl_mode: SslMode::Require,
                schema_default: None,
                replica_role: ReplicaRole::Primary,
            }),
            CategoryPayload::Env(EnvCategory {
                keys: vec!["K".into()],
                profile: "prod".into(),
                shape: EnvShape::Dotenv,
            }),
            CategoryPayload::Key(KeyCategory {
                key_kind: KeyKind::Ed25519,
                purpose: KeyPurpose::Signing,
                algo: "Ed25519".into(),
                public_key: None,
                fingerprint: "SHA256:abc".into(),
                bits: None,
                created_with: None,
            }),
            CategoryPayload::Note(NoteCategory {
                title: "Title".into(),
                content_type: NoteContentType::PlainText,
                summary: "Summary".into(),
                keywords: vec![],
            }),
            CategoryPayload::Otp(OtpCategory {
                service: "svc".into(),
                account: "user".into(),
                algo: OtpAlgo::SHA1,
                digits: 6,
                period: 30,
                issuer: None,
            }),
        ];

        for payload in &cases {
            let json = serde_json::to_string(payload).expect("serialize");
            assert!(!json.is_empty());
        }
    }
}
