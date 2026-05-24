//! `SshKeyCategory` — public metadata for `category = "ssh"` Secrets.

use serde::{Deserialize, Serialize};

/// SSH key algorithm discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshKeyType {
    /// RSA key.
    Rsa,
    /// Ed25519 key.
    Ed25519,
    /// ECDSA key.
    Ecdsa,
    /// DSA key (legacy).
    Dsa,
}

/// SSH authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshAuthMethod {
    /// Public-key authentication.
    Key,
    /// Password authentication.
    Password,
}

/// Public metadata fields for an `ssh` category Secret.
///
/// Maps the `#PublicMeta` shape from
/// `docs/arch/schemas/secret_storage/categories/ssh/ssh.cue`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshKeyCategory {
    /// Remote host address.
    pub host: String,

    /// SSH port (default 22).
    pub port: u16,

    /// SSH username.
    pub user: String,

    /// Authentication method used.
    pub auth_method: SshAuthMethod,

    /// Key algorithm, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<SshKeyType>,

    /// Public key fingerprint in `SHA256:<base64>` format.
    pub fingerprint: String,

    /// Key size in bits (e.g. 4096 for RSA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u32>,

    /// Known-hosts fingerprint for host verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_hosts_fp: Option<String>,

    /// Handle of a jump host Secret, if applicable (opaque URI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_host_handle: Option<String>,

    /// Custom `ProxyCommand` string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_command: Option<String>,
}
