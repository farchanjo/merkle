//! `ValueFormat` — encoding of the plaintext payload supplied to `put` / `rotate`.
//!
//! When the caller supplies the secret value over the HTTP transport (or CLI
//! stdin) it may already be base64-encoded — e.g. binary SSH keys, TLS
//! certificates, or JWK blobs.  `ValueFormat` tells the command layer how to
//! decode the raw bytes before passing them to the AEAD cipher.

use serde::{Deserialize, Serialize};

/// Encoding of the raw bytes that arrive on the wire before AEAD encryption.
///
/// Stored in `PutSecretCommand` and `RotateSecretCommand`.  The command's
/// `execute` method decodes according to this value before encrypting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueFormat {
    /// The payload is valid UTF-8 text.  The raw bytes are used directly
    /// (i.e., `value.into_bytes()`).  This is the default for interactive
    /// `merkle put` without `--base64`.
    #[default]
    Utf8,

    /// The payload is a Base64-standard-encoded blob.  The command will call
    /// `base64::decode(value)` before encrypting.  Use this for binary secrets
    /// (SSH private keys, certificates, etc.) or when piping from
    /// `base64`-producing tools.
    Base64,
}
