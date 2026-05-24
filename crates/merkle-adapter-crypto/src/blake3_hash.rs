//! BLAKE3 hash and keyed-MAC helpers (ADR-0009).

use merkle_types::{Blake3Hash, HmacSignature};

/// Compute the BLAKE3 hash of `data`.
pub(crate) fn hash(data: &[u8]) -> Blake3Hash {
    Blake3Hash::hash(data)
}

/// Compute a BLAKE3 keyed hash (MAC) over `data` using `key`.
///
/// Uses `blake3::keyed_hash` which is the canonical BLAKE3 keyed mode and acts
/// as a PRF suitable for audit-entry authentication.
pub(crate) fn keyed(key: &[u8; 32], data: &[u8]) -> HmacSignature {
    HmacSignature::compute(key, data)
}
