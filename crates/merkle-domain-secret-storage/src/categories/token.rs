//! `TokenCategory` — public metadata for `category = "token"` Secrets.

use serde::{Deserialize, Serialize};

/// HTTP authentication token type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    /// Bearer token (`Authorization: Bearer <token>`).
    Bearer,
    /// Basic auth credential.
    Basic,
    /// API key (e.g. `X-API-Key` header).
    Apikey,
    /// JSON Web Token.
    Jwt,
}

/// Public metadata fields for a `token` category Secret.
///
/// Maps the `#PublicMeta` shape from
/// `docs/arch/schemas/secret_storage/categories/token/token.cue`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenCategory {
    /// Service or API this token authenticates against.
    pub service: String,

    /// Token type (bearer, basic, apikey, jwt).
    pub token_type: TokenType,

    /// HTTP header name where the token is sent (default `"Authorization"`).
    pub header_name: String,

    /// OAuth scopes or permission identifiers granted by this token.
    pub scope: Vec<String>,

    /// Expiry timestamp (ISO-8601), if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,

    /// URL to revoke this token, if provided by the service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_url: Option<String>,

    /// Visible prefix of the token value (e.g. `"ghp_"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip() {
        let cat = TokenCategory {
            service: "github".into(),
            token_type: TokenType::Bearer,
            header_name: "Authorization".into(),
            scope: vec!["repo".into(), "read:org".into()],
            expires_at: None,
            revocation_url: None,
            prefix: Some("ghp_".into()),
        };
        let json = serde_json::to_string(&cat).expect("serialize");
        let parsed: TokenCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cat, parsed);
    }
}
