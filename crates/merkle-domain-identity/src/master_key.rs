//! `MasterKey` entity and `Argon2idParams` value object.
//!
//! Mirrors:
//! - `docs/arch/schemas/identity_and_sealing/master_key.cue`
//! - ADR-0005 (Argon2id KDF for passphrase fallback) + Amendment minimum-hardness floor

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use merkle_types::Rfc3339Timestamp;

use crate::DomainError;

// ---------------------------------------------------------------------------
// Argon2idParams
// ---------------------------------------------------------------------------

/// Minimum memory cost (64 MiB) mandated by ADR-0005 Amendment.
pub const MIN_M_COST: u32 = 65_536;

/// Minimum number of iterations mandated by ADR-0005 Amendment.
pub const MIN_T_COST: u32 = 3;

/// Minimum degree of parallelism mandated by ADR-0005 Amendment.
pub const MIN_P_COST: u32 = 1;

/// KDF parameters for a passphrase-derived `MasterKey`.
///
/// Construction is always through [`Argon2idParams::try_new`], which validates
/// the minimum-hardness floor from ADR-0005.  Stored alongside the wrapped
/// Vault Root Key when the passphrase fallback path was used.
///
/// The salt is a per-derivation 16-byte value held as raw bytes.  It is
/// serialized as URL-safe base64 (22 chars without padding) in external
/// representations.
///
/// ```
/// use merkle_domain_identity::Argon2idParams;
///
/// let params = Argon2idParams::try_new(65_536, 3, 1, [0u8; 16]).unwrap();
/// assert_eq!(params.m_cost(), 65_536);
/// assert_eq!(params.t_cost(), 3);
/// assert_eq!(params.p_cost(), 1);
/// ```
#[derive(Clone, Serialize, Deserialize, Zeroize)]
pub struct Argon2idParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    /// 16-byte per-derivation random salt.
    #[serde(with = "hex_bytes")]
    salt: [u8; 16],
}

impl fmt::Debug for Argon2idParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Argon2idParams")
            .field("m_cost", &self.m_cost)
            .field("t_cost", &self.t_cost)
            .field("p_cost", &self.p_cost)
            .field("salt", &"[REDACTED]")
            .finish()
    }
}

impl Argon2idParams {
    /// Construct and validate parameters against the minimum-hardness floor.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Argon2idBelowFloor`] if any parameter is below
    /// its minimum value.
    pub fn try_new(m_cost: u32, t_cost: u32, p_cost: u32, salt: [u8; 16]) -> Result<Self, DomainError> {
        if m_cost < MIN_M_COST {
            return Err(DomainError::Argon2idBelowFloor {
                field: "m_cost",
                got: m_cost,
                min: MIN_M_COST,
            });
        }
        if t_cost < MIN_T_COST {
            return Err(DomainError::Argon2idBelowFloor {
                field: "t_cost",
                got: t_cost,
                min: MIN_T_COST,
            });
        }
        if p_cost < MIN_P_COST {
            return Err(DomainError::Argon2idBelowFloor {
                field: "p_cost",
                got: p_cost,
                min: MIN_P_COST,
            });
        }
        Ok(Self { m_cost, t_cost, p_cost, salt })
    }

    /// Memory cost in KiB (>= [`MIN_M_COST`]).
    #[must_use]
    pub fn m_cost(&self) -> u32 {
        self.m_cost
    }

    /// Number of iterations (>= [`MIN_T_COST`]).
    #[must_use]
    pub fn t_cost(&self) -> u32 {
        self.t_cost
    }

    /// Degree of parallelism / lanes (>= [`MIN_P_COST`]).
    #[must_use]
    pub fn p_cost(&self) -> u32 {
        self.p_cost
    }

    /// The 16-byte per-derivation salt.
    #[must_use]
    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }
}

/// Serde helper: serializes `[u8; 16]` as lowercase hex.
mod hex_bytes {
    use serde::{Deserializer, Serializer, de};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s: &str = de::Deserialize::deserialize(d)?;
        let v = hex::decode(s).map_err(de::Error::custom)?;
        v.try_into()
            .map_err(|_| de::Error::custom("expected exactly 16 bytes (32 hex chars)"))
    }
}

// ---------------------------------------------------------------------------
// MasterKey
// ---------------------------------------------------------------------------

/// One version of the 32-byte symmetric key at the top of the key hierarchy.
///
/// The raw key material is **never** serialized or stored in this struct.
/// `MasterKey` is a reference entity: it holds metadata that locates the key
/// in the OS keychain (service ID, account, version) and, when the passphrase
/// fallback path was used, the KDF parameters needed to re-derive it.
///
/// Secret bytes are held in the in-memory `key_bytes` field, which is zeroed
/// on drop and **skipped** during serialization.  Only the metadata portions
/// serialize to/from persistent storage.
///
/// ```
/// use merkle_domain_identity::MasterKey;
/// use merkle_types::Rfc3339Timestamp;
///
/// let mk = MasterKey::new(1, Rfc3339Timestamp::now());
/// assert_eq!(mk.version(), 1);
/// assert!(mk.key_bytes().is_none()); // no key loaded yet
/// ```
#[derive(Serialize, Deserialize)]
pub struct MasterKey {
    /// Monotonically increasing counter starting at 1.
    version: u32,

    /// Fixed keychain service identifier for Merkle.
    service_id: String,

    /// Keychain account field, e.g. `"master-v1"`.
    account: String,

    /// AEAD cipher used when wrapping the Vault Root Key.
    algorithm: String,

    /// Timestamp of key generation.
    created_at: Rfc3339Timestamp,

    /// Timestamp of supersession (rotation).
    #[serde(skip_serializing_if = "Option::is_none")]
    rotated_at: Option<Rfc3339Timestamp>,

    /// Optional Argon2id parameters, present only for passphrase-derived keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    argon2id_params: Option<Argon2idParams>,

    /// In-memory 32-byte key material.  Never serialized; zeroed on drop.
    #[serde(skip)]
    key_bytes: Option<[u8; 32]>,
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterKey")
            .field("version", &self.version)
            .field("service_id", &self.service_id)
            .field("account", &self.account)
            .field("algorithm", &self.algorithm)
            .field("created_at", &self.created_at)
            .field("rotated_at", &self.rotated_at)
            .field("argon2id_params", &self.argon2id_params)
            .field("key_bytes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        if let Some(ref mut bytes) = self.key_bytes {
            bytes.zeroize();
        }
    }
}

impl Clone for MasterKey {
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            service_id: self.service_id.clone(),
            account: self.account.clone(),
            algorithm: self.algorithm.clone(),
            created_at: self.created_at,
            rotated_at: self.rotated_at,
            argon2id_params: self.argon2id_params.clone(),
            // key_bytes is intentionally NOT cloned — cloning key material
            // widens the attack surface.  Callers that need the key must go
            // through the keychain adapter.
            key_bytes: None,
        }
    }
}

impl MasterKey {
    /// Construct a metadata-only `MasterKey` (no key bytes loaded).
    ///
    /// Used when reading the reference from persistent storage before the
    /// actual key material is fetched from the OS keychain.
    #[must_use]
    pub fn new(version: u32, created_at: Rfc3339Timestamp) -> Self {
        Self {
            version,
            service_id: "dev.fapp.merkle".to_owned(),
            account: format!("master-v{version}"),
            algorithm: "XChaCha20-Poly1305".to_owned(),
            created_at,
            rotated_at: None,
            argon2id_params: None,
            key_bytes: None,
        }
    }

    /// Construct a passphrase-derived `MasterKey` with KDF parameters.
    #[must_use]
    pub fn new_passphrase_derived(
        version: u32,
        created_at: Rfc3339Timestamp,
        params: Argon2idParams,
    ) -> Self {
        let mut mk = Self::new(version, created_at);
        mk.argon2id_params = Some(params);
        mk
    }

    /// Load the 32-byte key material into memory.
    ///
    /// This method is called by the keychain adapter after a successful fetch.
    /// The bytes are zeroed on drop.
    pub fn load_key_bytes(&mut self, bytes: [u8; 32]) {
        self.key_bytes = Some(bytes);
    }

    /// Mark this version as superseded by a newer generation.
    pub fn mark_rotated(&mut self, rotated_at: Rfc3339Timestamp) {
        self.rotated_at = Some(rotated_at);
    }

    /// Return the version counter.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Return the keychain service identifier.
    #[must_use]
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    /// Return the keychain account name (`"master-v{N}"`).
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Return the in-memory key bytes, if loaded.
    ///
    /// Returns `None` until the keychain adapter calls [`Self::load_key_bytes`].
    ///
    /// **Never** pass this reference to any I/O path or log.
    #[must_use]
    pub fn key_bytes(&self) -> Option<&[u8; 32]> {
        self.key_bytes.as_ref()
    }

    /// Return the Argon2id KDF parameters, if this is a passphrase-derived key.
    #[must_use]
    pub fn argon2id_params(&self) -> Option<&Argon2idParams> {
        self.argon2id_params.as_ref()
    }

    /// Return the rotation timestamp, if this version has been superseded.
    #[must_use]
    pub fn rotated_at(&self) -> Option<Rfc3339Timestamp> {
        self.rotated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_new_valid_params_succeeds() {
        let params = Argon2idParams::try_new(65_536, 3, 1, [0u8; 16]);
        assert!(params.is_ok());
    }

    #[test]
    fn try_new_m_cost_below_floor_fails() {
        let err = Argon2idParams::try_new(32_768, 3, 1, [0u8; 16]).unwrap_err();
        assert!(matches!(err, DomainError::Argon2idBelowFloor { field: "m_cost", .. }));
    }

    #[test]
    fn try_new_t_cost_below_floor_fails() {
        let err = Argon2idParams::try_new(65_536, 2, 1, [0u8; 16]).unwrap_err();
        assert!(matches!(err, DomainError::Argon2idBelowFloor { field: "t_cost", .. }));
    }

    #[test]
    fn try_new_p_cost_zero_fails() {
        let err = Argon2idParams::try_new(65_536, 3, 0, [0u8; 16]).unwrap_err();
        assert!(matches!(err, DomainError::Argon2idBelowFloor { field: "p_cost", .. }));
    }

    #[test]
    fn master_key_new_has_no_key_bytes() {
        let mk = MasterKey::new(1, Rfc3339Timestamp::now());
        assert!(mk.key_bytes().is_none());
        assert_eq!(mk.version(), 1);
        assert_eq!(mk.account(), "master-v1");
        assert_eq!(mk.service_id(), "dev.fapp.merkle");
    }

    #[test]
    fn master_key_load_key_bytes() {
        let mut mk = MasterKey::new(1, Rfc3339Timestamp::now());
        mk.load_key_bytes([42u8; 32]);
        assert_eq!(mk.key_bytes(), Some(&[42u8; 32]));
    }

    #[test]
    fn master_key_clone_does_not_clone_key_bytes() {
        let mut mk = MasterKey::new(1, Rfc3339Timestamp::now());
        mk.load_key_bytes([0xABu8; 32]);
        let cloned = mk.clone();
        assert!(cloned.key_bytes().is_none(), "clone must not propagate key bytes");
    }

    #[test]
    fn master_key_debug_redacts_key_bytes() {
        let mut mk = MasterKey::new(1, Rfc3339Timestamp::now());
        mk.load_key_bytes([0u8; 32]);
        let debug = format!("{mk:?}");
        assert!(debug.contains("[REDACTED]"), "debug output must redact key bytes");
        assert!(!debug.contains("0, 0, 0"), "raw bytes must not appear in debug");
    }

    #[test]
    fn argon2id_params_debug_redacts_salt() {
        let params = Argon2idParams::try_new(65_536, 3, 1, [0xFFu8; 16]).unwrap();
        let debug = format!("{params:?}");
        assert!(debug.contains("[REDACTED]"), "salt must be redacted in Debug");
    }

    #[test]
    fn params_accessors_correct() {
        let params = Argon2idParams::try_new(131_072, 4, 2, [7u8; 16]).unwrap();
        assert_eq!(params.m_cost(), 131_072);
        assert_eq!(params.t_cost(), 4);
        assert_eq!(params.p_cost(), 2);
        assert_eq!(params.salt(), &[7u8; 16]);
    }
}
