//! `KeychainEntry` value object — locator for a secret in the OS keychain.
//!
//! ## Canonical naming
//!
//! ADR-0015 and the Gherkin scenarios in `init_vault.feature` / `unseal.feature`
//! declare a single canonical pair of identifiers for the Master Key entry:
//!
//! - service: [`KEYCHAIN_SERVICE`]  — `"dev.fapp.merkle"`
//! - account: [`KEYCHAIN_ACCOUNT_MASTER_KEY`] — `"master-v1"`
//!
//! Every caller that stores or retrieves the Master Key **must** use these
//! constants so that `init` and `unseal` always agree on the lookup key.

use serde::{Deserialize, Serialize};

use merkle_types::Rfc3339Timestamp;

/// Canonical OS Keychain service identifier for all Merkle Vault Agent entries.
///
/// Per ADR-0015 (`service = "dev.fapp.merkle"`).
pub const KEYCHAIN_SERVICE: &str = "dev.fapp.merkle";

/// Canonical OS Keychain account identifier for the wrapped Master Key (v1).
///
/// Per ADR-0015 (`account = "master-v1"`) and both `init_vault.feature`
/// and `unseal.feature` scenario backgrounds.
pub const KEYCHAIN_ACCOUNT_MASTER_KEY: &str = "master-v1";

/// Canonical OS Keychain account identifier for the operator JWT attestation
/// Ed25519 public key (ADR-0011 Amendment 6).
///
/// Non-Claude MCP clients that cannot issue slash commands store their
/// Ed25519 attestation public key under this account name. The agent
/// retrieves the key from `service = KEYCHAIN_SERVICE`, `account =
/// KEYCHAIN_ACCOUNT_OPERATOR_ATTESTATION` to verify `signed_config_flag` JWTs.
pub const KEYCHAIN_ACCOUNT_OPERATOR_ATTESTATION: &str = "merkle-operator-attestation";

/// A locator for a `MasterKey` entry in the OS keychain.
///
/// Carries the service name, account name, and the timestamp of the last
/// successful retrieval.  No key material is stored here; this is a pure
/// reference value object used by [`crate::VaultIdentity`] to hand off to the
/// `KeychainAdapter`.
///
/// ```
/// use merkle_domain_identity::KeychainEntry;
/// use merkle_types::Rfc3339Timestamp;
///
/// let entry = KeychainEntry::new(
///     "dev.fapp.merkle".to_owned(),
///     "master-v1".to_owned(),
///     Rfc3339Timestamp::now(),
/// );
/// assert_eq!(entry.service(), "dev.fapp.merkle");
/// assert_eq!(entry.account(), "master-v1");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeychainEntry {
    /// The keychain service identifier (always `"dev.fapp.merkle"`).
    service: String,

    /// The keychain account, e.g. `"master-v1"`.
    account: String,

    /// Timestamp of the last successful retrieval.
    last_seen: Rfc3339Timestamp,
}

impl KeychainEntry {
    /// Construct a new `KeychainEntry`.
    #[must_use]
    pub fn new(service: String, account: String, last_seen: Rfc3339Timestamp) -> Self {
        Self {
            service,
            account,
            last_seen,
        }
    }

    /// Convenience constructor for the canonical Merkle service identifier.
    ///
    /// `version` is appended to the canonical account prefix, e.g. version 1
    /// produces account `"master-v1"` (which equals [`KEYCHAIN_ACCOUNT_MASTER_KEY`]
    /// for the current active version).
    #[must_use]
    pub fn for_master_key(version: u32, last_seen: Rfc3339Timestamp) -> Self {
        Self {
            service: KEYCHAIN_SERVICE.to_owned(),
            account: format!("master-v{version}"),
            last_seen,
        }
    }

    /// Return the service name.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Return the account name.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Return the timestamp of the last successful retrieval.
    #[must_use]
    pub fn last_seen(&self) -> Rfc3339Timestamp {
        self.last_seen
    }

    /// Update the last-seen timestamp (called after a successful fetch).
    pub fn touch(&mut self, at: Rfc3339Timestamp) {
        self.last_seen = at;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_master_key_produces_correct_account() {
        let entry = KeychainEntry::for_master_key(3, Rfc3339Timestamp::now());
        assert_eq!(entry.service(), "dev.fapp.merkle");
        assert_eq!(entry.account(), "master-v3");
    }

    #[test]
    fn touch_updates_timestamp() {
        let t1 = Rfc3339Timestamp::now();
        let mut entry = KeychainEntry::for_master_key(1, t1);
        let t2 = Rfc3339Timestamp::now();
        entry.touch(t2);
        assert_eq!(entry.last_seen(), t2);
    }

    /// Canonical naming constants must match ADR-0015 + Gherkin spec literals.
    #[test]
    fn keychain_naming_constants_match_spec() {
        assert_eq!(KEYCHAIN_SERVICE, "dev.fapp.merkle");
        assert_eq!(KEYCHAIN_ACCOUNT_MASTER_KEY, "master-v1");
    }

    /// `for_master_key(1)` must resolve to the canonical account name.
    #[test]
    fn for_master_key_v1_equals_canonical_account() {
        let entry = KeychainEntry::for_master_key(1, Rfc3339Timestamp::now());
        assert_eq!(entry.service(), KEYCHAIN_SERVICE);
        assert_eq!(entry.account(), KEYCHAIN_ACCOUNT_MASTER_KEY);
    }

    /// ADR-0011 Amendment 6: operator attestation account constant must match spec literal.
    #[test]
    fn operator_attestation_account_matches_spec() {
        assert_eq!(
            KEYCHAIN_ACCOUNT_OPERATOR_ATTESTATION, "merkle-operator-attestation",
            "ADR-0011 Amendment 6 spec literal must match"
        );
        // Both constants share the same service.
        assert_eq!(KEYCHAIN_SERVICE, "dev.fapp.merkle");
    }
}
