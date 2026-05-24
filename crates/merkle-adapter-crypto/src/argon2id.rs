//! Argon2id key derivation with minimum-hardness floor (ADR-0005 + Amendment).
//!
//! The floor is enforced independently here even though `Argon2idParams::try_new`
//! also validates it.  Defense-in-depth: a caller might construct `Argon2idParams`
//! via deserialization paths that bypass `try_new`.

use argon2::{Algorithm, Argon2, Params, Version};
use merkle_domain_identity::Argon2idParams;
use merkle_ports::error::CryptoError;

// Floor constants mirror those in `merkle-domain-identity` to avoid a
// cross-crate dependency on the private constants.
const MIN_M_COST: u32 = 65_536;
const MIN_T_COST: u32 = 3;
const MIN_P_COST: u32 = 1;

/// Derive a 32-byte key from `passphrase` using Argon2id with the given `params`.
///
/// # Errors
///
/// - [`CryptoError::InvalidArgon2idParams`] when any parameter is below the
///   minimum-hardness floor or `argon2::Params::new` rejects the values.
/// - [`CryptoError::Backend`] on internal Argon2 errors.
pub(crate) fn derive(
    passphrase: &[u8],
    salt: &[u8; 16],
    params: &Argon2idParams,
) -> Result<[u8; 32], CryptoError> {
    // Enforce floor (belt-and-suspenders; Argon2idParams::try_new also validates).
    if params.m_cost() < MIN_M_COST || params.t_cost() < MIN_T_COST || params.p_cost() < MIN_P_COST
    {
        return Err(CryptoError::InvalidArgon2idParams);
    }

    let argon2_params = Params::new(params.m_cost(), params.t_cost(), params.p_cost(), Some(32))
        .map_err(|e| CryptoError::Backend(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt.as_slice(), &mut output)
        .map_err(|e| CryptoError::Backend(e.to_string()))?;

    Ok(output)
}
