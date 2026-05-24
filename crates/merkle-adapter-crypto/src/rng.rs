//! OsRng wrappers and entropy-gate check (ADR-0004 Amendment).
//!
//! On Linux, reads `/proc/sys/kernel/random/entropy_avail` and returns an
//! error when below 128 bits.  On all other platforms, `OsRng` blocks until
//! the OS CSPRNG is seeded; we trust that behaviour and succeed immediately.
//!
//! Uses `rand_core 0.6` `OsRng` which is the version required by
//! `ed25519-dalek 2.x` and `chacha20poly1305 0.10`.

use rand_core::{OsRng, RngCore};

use crate::CryptoAdapterError;

/// Check that the OS entropy pool is sufficiently seeded.
///
/// On Linux this reads `/proc/sys/kernel/random/entropy_avail`.  On other
/// platforms this is a no-op (the OS CSPRNG blocks internally until seeded).
///
/// # Errors
///
/// Returns [`CryptoAdapterError::EntropyUnavailable`] on Linux when the pool
/// is below 128 bits.
// The Result return is necessary on Linux; on non-Linux platforms the function
// trivially returns Ok(()) but must share the same signature for callers.
#[expect(
    clippy::unnecessary_wraps,
    reason = "on non-Linux platforms the body is empty but callers require a unified Result API"
)]
pub fn assert_entropy_gate() -> Result<(), CryptoAdapterError> {
    #[cfg(target_os = "linux")]
    {
        /// Minimum entropy pool size (bits) required before encrypting on Linux.
        const MIN_ENTROPY_BITS: u32 = 128;

        use std::fs;

        let content = fs::read_to_string("/proc/sys/kernel/random/entropy_avail")
            .map_err(|e| CryptoAdapterError::EntropyUnavailable(e.to_string()))?;

        let bits: u32 = content
            .trim()
            .parse()
            .map_err(|_| {
                CryptoAdapterError::EntropyUnavailable(
                    "failed to parse /proc/sys/kernel/random/entropy_avail".to_owned(),
                )
            })?;

        if bits < MIN_ENTROPY_BITS {
            return Err(CryptoAdapterError::EntropyUnavailable(format!(
                "entropy_avail={bits} is below the minimum threshold of {MIN_ENTROPY_BITS}"
            )));
        }
    }

    Ok(())
}

/// Fill a 32-byte array with cryptographically secure random bytes.
pub(crate) fn random_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Fill a 24-byte array with cryptographically secure random bytes.
pub(crate) fn random_24() -> [u8; 24] {
    let mut buf = [0u8; 24];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Fill a 16-byte array with cryptographically secure random bytes.
pub(crate) fn random_16() -> [u8; 16] {
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    buf
}
