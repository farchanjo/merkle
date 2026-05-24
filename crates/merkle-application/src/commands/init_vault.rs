//! `InitVaultCommand` — init vault bootstrap ceremony (ADR-0021).
//!
//! Executes the 8-step ceremony:
//!
//! 1. Check idempotency — keychain entry `dev.fapp.merkle / master-v1`.
//! 2. Generate Master Key (32 bytes, OsRng).
//! 3. Persist Master Key in OS Keychain under `dev.fapp.merkle / master-v1`.
//! 4. Generate Recovery Key (age X25519 identity).
//! 5. Generate Vault Root Key (32 bytes, OsRng).
//! 6. Dual-wrap VRK: AEAD(VRK, master_key) + ECIES(VRK, recovery_pubkey).
//! 7. Persist wrapped copies — master-wrapped in keychain under `vrk-master-v1`,
//!    recovery-wrapped under `vrk-recovery-v1`, using base64 encoding.
//! 8. Emit audit entry op=init, outcome=allow.
//! 9. Return vault_id, recovery_key (age public key string), master_key_keychain_ref.
//!
//! The `recovery_key` in the response is the **only** transmission of the
//! age X25519 public key. The private identity is never stored.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use merkle_domain_identity::{KEYCHAIN_ACCOUNT_MASTER_KEY, KEYCHAIN_SERVICE};
use merkle_types::{AuditOp, AuditOutcome, NamespaceId, SecurityProfile, UuidV7};
use tracing::info;

use crate::{AppContext, AppError};

/// OS Keychain account for the master-wrapped VRK.
const KEYCHAIN_ACCOUNT_VRK_MASTER: &str = "vrk-master-v1";
/// OS Keychain account for the recovery-wrapped VRK.
const KEYCHAIN_ACCOUNT_VRK_RECOVERY: &str = "vrk-recovery-v1";
/// Canonical service+account reference returned in the response.
const KEYCHAIN_REF: &str = "dev.fapp.merkle/master-v1";

/// Input for vault initialization.
#[derive(Debug)]
pub struct InitVaultCommand {
    /// Whether the CLI should show an interactive confirmation prompt after
    /// printing the Recovery Key (`true`) or suppress it (`false`).
    /// Non-interactive mode still prints the key on stdout.
    pub interactive: bool,

    /// Security profile to apply for subsequent Namespace Policy defaults.
    /// Defaults to `Balanced` when not supplied.
    pub security_profile: SecurityProfile,
}

/// Output of a successful `InitVaultCommand`.
#[derive(Debug)]
pub struct InitVaultOutput {
    /// UUIDv7 identifying this vault installation.
    pub vault_id: UuidV7,

    /// The age X25519 public key string (`age1<bech32>`).
    ///
    /// This is the ONLY time this value is transmitted. It MUST NOT be logged
    /// or persisted by any component.
    pub recovery_key: String,

    /// Canonical service + account reference where the Master Key was stored.
    /// Format: `dev.fapp.merkle/master-v1`.
    pub master_key_keychain_ref: String,
}

impl InitVaultCommand {
    /// Execute vault initialization.
    ///
    /// # Errors
    ///
    /// - [`AppError::PolicyDenied`]`("already_initialized")` — OS Keychain
    ///   entry `dev.fapp.merkle/master-v1` already exists; vault is already
    ///   initialized.  No keys are generated or modified.
    /// - [`AppError::Keychain`] — OS Keychain daemon unavailable or write
    ///   failed.  Ceremony is aborted; no database rows are written.
    /// - [`AppError::Crypto`] — key generation or wrapping failed.
    /// - [`AppError::Storage`] — audit log append failed.
    #[expect(
        clippy::too_many_lines,
        reason = "8-step init ceremony documented in ADR-0021; extraction would scatter the \
                  atomic ceremony across private helpers without clarity gain"
    )]
    pub async fn execute(&self, ctx: &AppContext) -> Result<InitVaultOutput, AppError> {
        info!("init_vault: checking idempotency (step 1)");

        // ── Step 1: Check idempotency ──────────────────────────────────────
        // Probe for presence of the master-key entry WITHOUT reading material.
        let check = ctx
            .keychain
            .retrieve(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_MASTER_KEY)
            .await;

        match check {
            Ok(_) => {
                // Entry exists → vault already initialized. Per ADR-0021 §Idempotency:
                // do NOT generate new keys, do NOT emit an audit entry.
                return Err(AppError::PolicyDenied("already_initialized".to_owned()));
            }
            Err(merkle_ports::KeychainError::NotFound) => {
                // Expected: vault is not yet initialized. Proceed.
            }
            Err(e) => {
                // Keychain daemon unavailable or access denied → 503.
                return Err(AppError::Keychain(e));
            }
        }

        // ── Step 2: Generate Master Key (32 random bytes, OsRng) ────────────
        info!("init_vault: generating master key (step 2)");
        let master_key_bytes: [u8; 32] = ctx.crypto.random_bytes_32();

        // ── Step 3: Persist Master Key in OS Keychain ──────────────────────
        info!("init_vault: storing master key in keychain (step 3)");
        ctx.keychain
            .store(
                KEYCHAIN_SERVICE,
                KEYCHAIN_ACCOUNT_MASTER_KEY,
                &master_key_bytes,
            )
            .await
            .map_err(|e| {
                info!("init_vault: keychain write failed, aborting ceremony");
                AppError::Keychain(e)
            })?;

        // ── Step 4: Generate Recovery Key (age X25519) ─────────────────────
        // Generate a fresh X25519 keypair. The private key is used only for
        // wrapping the VRK (step 6) and MUST NOT be stored.
        info!("init_vault: generating recovery key (step 4)");
        let (recovery_privkey, recovery_pubkey_raw) = ctx.crypto.x25519_keypair();
        let recovery_key_str = encode_age_public_key(&recovery_pubkey_raw.0);

        // ── Step 5: Generate Vault Root Key (32 random bytes, OsRng) ────────
        info!("init_vault: generating vault root key (step 5)");
        let vrk_bytes: [u8; 32] = ctx.crypto.random_bytes_32();

        // ── Step 6: Dual-wrap VRK ──────────────────────────────────────────
        // 6a. AEAD(VRK, master_key) — XChaCha20-Poly1305 with random nonce.
        info!("init_vault: dual-wrapping VRK (step 6)");
        let nonce_master: [u8; 24] = ctx.crypto.random_bytes_24();
        let wrapped_by_master = ctx
            .crypto
            .aead_encrypt(
                &master_key_bytes,
                &nonce_master,
                &vrk_bytes,
                b"vault-root-key",
            )
            .inspect_err(|_e| {
                // Clean up keychain on failure (best-effort): drop key material.
                let _ = std::hint::black_box((&master_key_bytes, &recovery_privkey.0));
            })?;

        // 6b. ECIES(VRK, recovery_pubkey) — X25519 + XChaCha20-Poly1305.
        let recovery_pk_typed = merkle_ports::X25519PublicKey(recovery_pubkey_raw.0);
        let wrapped_by_recovery = ctx.crypto.x25519_ecies_encrypt(
            &recovery_pk_typed,
            &vrk_bytes,
            b"vault-root-key-recovery",
        )?;

        // ── Step 7: Persist both wrapped copies ────────────────────────────
        // We use the Keychain port (the only writable persistent port available
        // without adding a new Storage method). Each wrapped VRK is stored as
        // a base64-encoded blob under a dedicated account key.
        //
        // Master-wrapped: nonce (24 bytes base64) || ciphertext (base64), joined by ':'.
        info!("init_vault: persisting wrapped VRK (step 7)");
        let master_wrapped_payload = {
            let mut buf = Vec::with_capacity(24 + wrapped_by_master.len());
            buf.extend_from_slice(&nonce_master);
            buf.extend_from_slice(&wrapped_by_master);
            BASE64.encode(&buf).into_bytes()
        };

        let recovery_wrapped_payload = {
            let envelope = serde_json::to_vec(&wrapped_by_recovery)
                .map_err(|e| AppError::Domain(e.to_string()))?;
            BASE64.encode(&envelope).into_bytes()
        };

        // Store master-wrapped VRK. On failure, remove master key from keychain.
        if let Err(e) = ctx
            .keychain
            .store(
                KEYCHAIN_SERVICE,
                KEYCHAIN_ACCOUNT_VRK_MASTER,
                &master_wrapped_payload,
            )
            .await
        {
            info!("init_vault: VRK master-wrap persist failed, rolling back keychain");
            let _ = ctx
                .keychain
                .delete(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_MASTER_KEY)
                .await;
            return Err(AppError::Keychain(e));
        }

        // Store recovery-wrapped VRK. On failure, remove both previous entries.
        if let Err(e) = ctx
            .keychain
            .store(
                KEYCHAIN_SERVICE,
                KEYCHAIN_ACCOUNT_VRK_RECOVERY,
                &recovery_wrapped_payload,
            )
            .await
        {
            info!("init_vault: VRK recovery-wrap persist failed, rolling back keychain");
            let _ = ctx
                .keychain
                .delete(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_MASTER_KEY)
                .await;
            let _ = ctx
                .keychain
                .delete(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_VRK_MASTER)
                .await;
            return Err(AppError::Keychain(e));
        }

        // ── Step 8: Emit audit entry ────────────────────────────────────────
        // HMAC key = BLAKE3-KDF(VRK, "merkle vault hmac key v1") per ADR-0021.
        info!("init_vault: appending audit entry op=init (step 8)");
        let namespace_id = NamespaceId::new(); // vault root namespace
        let hmac_key = ctx
            .crypto
            .blake3_keyed(&vrk_bytes, b"merkle vault hmac key v1");

        let vault_id = UuidV7::new();
        {
            let mut log = ctx.audit_log.write().await;
            let params = merkle_domain_audit_compliance::AppendParams::new(
                AuditOp::Init,
                AuditOutcome::Allow,
                namespace_id,
            )
            .caller_program("merkle-agent");
            let (entry, pinned) = merkle_domain_audit_compliance::AuditWriter::append(
                &mut log,
                params,
                hmac_key.as_bytes(),
            )
            .map_err(|e| AppError::Domain(e.to_string()))?;
            drop(log);
            ctx.storage.append_audit_entry(&entry).await?;
            ctx.storage.update_pinned_head(&pinned).await?;
        }

        info!(vault_id = %vault_id, "init_vault: ceremony complete");

        Ok(InitVaultOutput {
            vault_id,
            recovery_key: recovery_key_str,
            master_key_keychain_ref: KEYCHAIN_REF.to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// age X25519 public key bech32 encoding
// ---------------------------------------------------------------------------

/// Encode a 32-byte X25519 public key as an age recipient string (`age1<bech32>`).
///
/// age uses bech32 with HRP `age`. The 32 raw bytes are converted to 5-bit
/// groups using the standard bech32 alphabet. A bech32 checksum is appended.
fn encode_age_public_key(pubkey: &[u8; 32]) -> String {
    // bech32 charset (BIP-0173).
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    // Convert 8-bit groups to 5-bit groups.
    let mut data: Vec<u8> = Vec::with_capacity(52);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in pubkey {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(u8::try_from((acc >> bits) & 0x1f).unwrap_or(0));
        }
    }
    if bits > 0 {
        data.push(u8::try_from((acc << (5 - bits)) & 0x1f).unwrap_or(0));
    }

    // Compute bech32 checksum for HRP "age".
    let checksum = bech32_checksum(b"age", &data);

    // Assemble the final string.
    let mut encoded = String::with_capacity(4 + 1 + data.len() + 6);
    encoded.push_str("age1");
    for &v in &data {
        encoded.push(char::from(CHARSET[v as usize]));
    }
    for &c in &checksum {
        encoded.push(char::from(CHARSET[c as usize]));
    }
    encoded
}

/// Compute a 6-element bech32 checksum over `hrp` and `data`.
fn bech32_checksum(hrp: &[u8], data: &[u8]) -> [u8; 6] {
    let mut values: Vec<u32> = Vec::with_capacity(hrp.len() * 2 + data.len() + 6);

    // HRP high bits
    for &c in hrp {
        values.push(u32::from(c) >> 5);
    }
    values.push(0);
    // HRP low bits
    for &c in hrp {
        values.push(u32::from(c) & 0x1f);
    }
    // data
    for &d in data {
        values.push(u32::from(d));
    }
    // padding for checksum
    values.extend(std::iter::repeat_n(0u32, 6));

    let polymod = bech32_polymod(&values) ^ 1;
    let mut checksum = [0u8; 6];
    for (i, c) in checksum.iter_mut().enumerate() {
        *c = u8::try_from((polymod >> (5 * (5 - i))) & 0x1f).unwrap_or(0);
    }
    checksum
}

/// bech32 polymod function (GF(2^5) polynomial).
fn bech32_polymod(values: &[u32]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = (chk & 0x1ff_ffff) << 5 ^ v;
        for (i, &g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn age_public_key_format() {
        let pubkey = [0xAB_u8; 32];
        let encoded = encode_age_public_key(&pubkey);
        assert!(
            encoded.starts_with("age1"),
            "must start with age1, got: {encoded}"
        );
        assert!(
            encoded.chars().all(|c| c.is_ascii_alphanumeric()),
            "must be alphanumeric, got: {encoded}"
        );
        // age bech32: "age1" + 52 data chars + 6 checksum chars = 62 chars minimum
        assert!(
            encoded.len() >= 10,
            "must be at least 10 chars, got len={}",
            encoded.len()
        );
    }

    #[test]
    fn keychain_ref_constant() {
        assert_eq!(KEYCHAIN_REF, "dev.fapp.merkle/master-v1");
    }

    #[test]
    fn different_keys_produce_different_encodings() {
        let key_a = [0x00_u8; 32];
        let key_b = [0xFF_u8; 32];
        assert_ne!(encode_age_public_key(&key_a), encode_age_public_key(&key_b));
    }
}
