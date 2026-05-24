//! `UnsealProtocol` — pure domain service for the unseal sequence.
//!
//! This service contains no I/O and no runtime state.  It orchestrates the
//! transition `Sealed → Unsealing → Unsealed` using data supplied by the
//! caller (the application layer or a port adapter).
//!
//! ## Adapter seam
//!
//! Actual Argon2id derivation and XChaCha20-Poly1305 unwrapping are performed
//! by the `CryptoAdapter` (a driven port).  The domain service declares the
//! stub signature here so that callers compile against the interface; the
//! adapter provides the concrete implementation.

use crate::{Argon2idParams, DomainError, MasterKey};

/// Domain service that orchestrates the unseal protocol.
///
/// All methods are free functions (no instance state).  The application layer
/// calls these in sequence:
///
/// 1. [`UnsealProtocol::evaluate_preconditions`] — validate runtime flags.
/// 2. Fetch the Master Key from the keychain adapter (application layer).
/// 3. [`UnsealProtocol::derive_master_key_from_passphrase`] — fallback path.
/// 4. Call the crypto adapter to unwrap the Vault Root Key.
/// 5. Call [`VaultIdentity::complete_unseal`](crate::VaultIdentity::complete_unseal).
///
/// The domain service does **not** own the adapter references; those are
/// injected by the application layer at call time.
pub struct UnsealProtocol;

impl UnsealProtocol {
    /// Evaluate unseal preconditions and return the first violation.
    ///
    /// Delegates to [`crate::UnsealPreconditions::validate`] so that the
    /// application layer can call this without importing the preconditions
    /// module directly.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::UnsealPreconditionFailed`] on any violation.
    pub fn evaluate_preconditions(
        preconditions: crate::UnsealPreconditions,
    ) -> Result<(), DomainError> {
        preconditions.validate()
    }

    /// Stub: derive a `MasterKey` from an operator passphrase using Argon2id.
    ///
    /// **This method is a domain-layer stub.**  The actual derivation is
    /// performed by the `CryptoAdapter` (driven port).  The stub exists so
    /// that callers compile against the signature.
    ///
    /// The application layer MUST replace this call with the concrete adapter
    /// invocation before shipping.
    ///
    /// # Errors
    ///
    /// Always returns [`DomainError::DerivationNotImplemented`] in the stub.
    ///
    /// # Security
    ///
    /// `passphrase` is accepted as a byte slice to avoid UTF-8 transcoding
    /// overhead and to allow clearing the buffer in the caller.  The caller
    /// is responsible for zeroizing the passphrase buffer after this call.
    pub fn derive_master_key_from_passphrase(
        _passphrase: &[u8],
        _params: &Argon2idParams,
    ) -> Result<MasterKey, DomainError> {
        Err(DomainError::DerivationNotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use merkle_types::SecurityProfile;

    use super::*;
    use crate::UnsealPreconditions;

    #[test]
    fn evaluate_preconditions_ok() {
        let pre = UnsealPreconditions {
            security_profile: SecurityProfile::Balanced,
            mlock_succeeded: true,
            entropy_seeded: true,
            keychain_reachable: true,
        };
        assert!(UnsealProtocol::evaluate_preconditions(pre).is_ok());
    }

    #[test]
    fn evaluate_preconditions_entropy_failure() {
        let pre = UnsealPreconditions {
            security_profile: SecurityProfile::Balanced,
            mlock_succeeded: true,
            entropy_seeded: false,
            keychain_reachable: true,
        };
        assert!(UnsealProtocol::evaluate_preconditions(pre).is_err());
    }

    #[test]
    fn derive_master_key_stub_returns_not_implemented() {
        let params = Argon2idParams::try_new(65_536, 3, 1, [0u8; 16]).unwrap();
        let err = UnsealProtocol::derive_master_key_from_passphrase(b"passphrase", &params)
            .unwrap_err();
        assert!(matches!(err, DomainError::DerivationNotImplemented));
    }
}
