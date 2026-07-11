//! `RevealSecretCommand` — authorize and decrypt a secret's private blob.
//!
//! Evaluation order (mirrors `PolicyEvaluator`):
//! 1. Vault must be Unsealed.
//! 2. `decision::evaluate` (access mediation — slash command + OOB threshold).
//! 3. When OOB is required: dispatch OOB challenge, await resolution, verify
//!    Ed25519 signature.
//! 4. Decrypt the `PrivateBlob` using the namespace DEK.
//! 5. Append `AuditEntry`.

use std::time::Duration;

use merkle_domain_access_mediation::{
    companion_device::CompanionDevice, decision, operator_confirmation::OperatorConfirmation,
    reveal_authorization::RevealAuthorization,
};
use merkle_domain_identity::keychain_entry::KEYCHAIN_ACCOUNT_OPERATOR_ATTESTATION;
use merkle_domain_identity::keychain_entry::KEYCHAIN_SERVICE;
use merkle_types::{
    AuditOp, AuditOutcome, ChallengeId, CompanionDeviceClass, Handle, NamespaceId, OobChannel,
    Rfc3339Timestamp, SecurityProfile, Sensitivity,
};
use tracing::info;

use crate::{
    AppContext, AppError,
    jwt_verifier::{Ed25519PublicKey, JwtAttestationVerifier},
};

/// Input for reveal-secret.
#[derive(Debug)]
pub struct RevealSecretCommand {
    /// Namespace owning the secret.
    pub namespace_id: NamespaceId,

    /// Vault URI of the secret to reveal.
    pub handle: Handle,

    /// Two-flag operator confirmation (slash command + OOB ack).
    ///
    /// When `operator_confirmation.signed_config_flag` is `Some`, the
    /// adapter layer pre-validates the JWT and sets `slash_command = false`
    /// (non-Claude client). The command re-verifies the JWT internally using
    /// the operator public key from the OS keychain.
    pub operator_confirmation: OperatorConfirmation,

    /// Challenge identifier used to bind a `signed_config_flag` JWT.
    ///
    /// Required when `operator_confirmation.signed_config_flag.is_some()`;
    /// ignored otherwise.  The JWT's `challenge_id` claim MUST equal this
    /// value for the attestation to be accepted.
    pub challenge_id: Option<ChallengeId>,

    /// Sensitivity of the secret (caller knows from a prior `describe` call).
    pub sensitivity: Sensitivity,

    /// Namespace OOB threshold: sensitivity level at which OOB is required.
    pub oob_threshold: Sensitivity,

    /// Active vault security profile.
    pub security_profile: SecurityProfile,

    /// 32-byte plaintext namespace DEK used to decrypt the blob.
    pub dek_bytes: [u8; 32],

    /// The enrolled Companion Device to receive the OOB challenge (required
    /// when OOB is needed; optional otherwise).
    pub companion_device: Option<CompanionDevice>,

    /// OOB channel to use when dispatching the challenge.
    pub oob_channel: OobChannel,

    /// Timeout for awaiting an OOB resolution.
    pub oob_timeout: Duration,

    /// Required device class per namespace policy.
    pub required_device_class: CompanionDeviceClass,
}

/// Output of a successful `RevealSecretCommand`.
#[derive(Debug)]
pub struct RevealSecretOutput {
    /// Decrypted plaintext bytes.
    ///
    /// The driving adapter MUST zeroize this buffer once it has been consumed
    /// (e.g., written to a tempfile or a named pipe). The application layer
    /// cannot enforce this contract in safe Rust.
    pub plaintext: Vec<u8>,
}

impl RevealSecretCommand {
    /// Execute reveal-secret.
    ///
    /// # Errors
    ///
    /// - [`AppError::VaultSealed`] — vault not Unsealed.
    /// - [`AppError::PolicyDenied`] — access mediation denied the request.
    /// - [`AppError::NotFound`] — secret not found for the handle.
    /// - [`AppError::Oob`] — OOB dispatch or resolution failed.
    /// - [`AppError::Crypto`] — AEAD decryption failed.
    /// - [`AppError::Storage`] — storage or audit write failed.
    #[expect(
        clippy::too_many_lines,
        reason = "policy evaluation + OOB challenge + decrypt + audit is inherently multi-step; extracting sub-functions would obscure the security-critical control flow"
    )]
    pub async fn execute(&self, ctx: &AppContext) -> Result<RevealSecretOutput, AppError> {
        ctx.require_unsealed().await?;

        info!(handle = %self.handle, "reveal_secret: evaluating access policy");

        // 0. JWT attestation path: if the client supplied a signed_config_flag
        //    and did NOT set slash_command, verify the JWT and treat success as
        //    equivalent to slash_command=true (ADR-0011 Amendment 6).
        if let Some(ref scf) = self.operator_confirmation.signed_config_flag
            && !self.operator_confirmation.slash_command
        {
            // Retrieve operator Ed25519 public key from OS keychain.
            let pubkey_bytes = ctx
                .keychain
                .retrieve(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_OPERATOR_ATTESTATION)
                .await
                .map_err(|_| {
                    AppError::PolicyDenied("invalid_signed_config_flag: key_not_enrolled".into())
                })?;

            let key_arr: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
                AppError::PolicyDenied("invalid_signed_config_flag: key malformed".into())
            })?;
            let operator_pubkey = Ed25519PublicKey(key_arr);

            let challenge_id = self.challenge_id.ok_or_else(|| {
                AppError::PolicyDenied("invalid_signed_config_flag: missing challenge_id".into())
            })?;

            let flag = crate::jwt_verifier::SignedConfigFlag {
                jwt: scf.jwt.clone(),
                key_id: scf.key_id.clone(),
            };
            JwtAttestationVerifier::verify(
                &flag,
                &challenge_id,
                &operator_pubkey,
                &Rfc3339Timestamp::now(),
            )?;
            // JWT verified — operator confirmation is treated as satisfied.
            // Continue with the rest of the policy evaluation; slash_command
            // equivalence is already reflected in `slash_confirmed()`.
        }

        let oob_required = self.sensitivity >= self.oob_threshold
            || self.security_profile == SecurityProfile::Paranoid;

        // Caller-supplied oob_ack is never trusted as authorization. When OOB is
        // required we dispatch a real challenge, await a resolution from the
        // OobNotifier, and only then set oob_ack for policy evaluation.
        let mut effective_confirmation = self.operator_confirmation.clone();
        if oob_required {
            effective_confirmation.oob_ack = false;
            let device = self.companion_device.clone().unwrap_or_else(software_placeholder_device);
            let challenge_id = ChallengeId::new();
            let challenge = merkle_domain_access_mediation::oob::challenge::OobChallenge {
                challenge_id,
                namespace_id: self.namespace_id,
                secret_handle: self.handle.clone(),
                sensitivity: self.sensitivity,
                oob_channel: self.oob_channel,
                // Wall-clock expiry is enforced by the OobNotifier timeout;
                // stamp "now" as a lower bound for clients that display the field.
                expires_at: Rfc3339Timestamp::now(),
                request_nonce: ctx.crypto.random_bytes_32(),
                envelope: None,
            };

            if let Err(e) = ctx.oob.dispatch(&challenge, &device).await {
                let hmac_key = ctx.require_hmac_key().await?;
                let params = merkle_domain_audit_compliance::AppendParams::new(
                    AuditOp::Reveal,
                    AuditOutcome::Deny,
                    self.namespace_id,
                )
                .handle(self.handle.clone())
                .sensitivity(self.sensitivity)
                .denial_reason("oob_dispatch_failed")
                .caller_program("merkle-agent");
                crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;
                return Err(AppError::PolicyDenied(format!("oob_dispatch_failed: {e}")));
            }
            let resolution = match ctx
                .oob
                .await_resolution(challenge_id, self.oob_timeout)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    let hmac_key = ctx.require_hmac_key().await?;
                    let params = merkle_domain_audit_compliance::AppendParams::new(
                        AuditOp::Reveal,
                        AuditOutcome::Deny,
                        self.namespace_id,
                    )
                    .handle(self.handle.clone())
                    .sensitivity(self.sensitivity)
                    .denial_reason("oob_timeout_or_failed")
                    .caller_program("merkle-agent");
                    crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;
                    return Err(AppError::PolicyDenied(format!("oob_timeout_or_failed: {e}")));
                }
            };

            if !resolution.is_approved() {
                let hmac_key = ctx.require_hmac_key().await?;
                let params = merkle_domain_audit_compliance::AppendParams::new(
                    AuditOp::Reveal,
                    AuditOutcome::Deny,
                    self.namespace_id,
                )
                .handle(self.handle.clone())
                .sensitivity(self.sensitivity)
                .denial_reason("oob_not_approved")
                .caller_program("merkle-agent");
                crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;
                return Err(AppError::PolicyDenied("oob_not_approved".into()));
            }

            // Hardware-class devices attach an Ed25519 signature over the
            // request_nonce; verify when a non-zero enrolled pubkey is present.
            // Software / terminal OOB channels may approve without a signature
            // (or with a transport-only stub signature that has no pubkey).
            if device.ed25519_pubkey != [0u8; 32]
                && let Some(sig) = resolution.device_signature.as_ref()
            {
                let pk = merkle_ports::Ed25519PublicKey(device.ed25519_pubkey);
                if let Err(e) = ctx.crypto.ed25519_verify(&pk, &challenge.request_nonce, sig) {
                    let hmac_key = ctx.require_hmac_key().await?;
                    let params = merkle_domain_audit_compliance::AppendParams::new(
                        AuditOp::Reveal,
                        AuditOutcome::Deny,
                        self.namespace_id,
                    )
                    .handle(self.handle.clone())
                    .sensitivity(self.sensitivity)
                    .denial_reason("oob_signature_invalid")
                    .caller_program("merkle-agent");
                    crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;
                    return Err(AppError::PolicyDenied(format!(
                        "oob_signature_invalid: {e}"
                    )));
                }
            }

            effective_confirmation.oob_ack = true;
            info!(%challenge_id, "reveal_secret: OOB challenge approved");
        }

        // 1. Resolve the companion device class (Software if no device enrolled).
        let bound_device_class = self
            .companion_device
            .as_ref()
            .map_or(CompanionDeviceClass::Software, |d| d.class);

        // 2. Evaluate Operator Confirmation policy (with verified oob_ack).
        let authorization = decision::evaluate(
            &effective_confirmation,
            self.sensitivity,
            self.oob_threshold,
            self.security_profile,
            bound_device_class,
            self.required_device_class,
        )
        .map_err(|e| AppError::Domain(e.to_string()))?;

        match &authorization {
            RevealAuthorization::Deny { reason } => {
                // Audit denied attempt (BUG-06: persist-then-advance atomically).
                let hmac_key = ctx.require_hmac_key().await?;
                let params = merkle_domain_audit_compliance::AppendParams::new(
                    AuditOp::Reveal,
                    AuditOutcome::Deny,
                    self.namespace_id,
                )
                .handle(self.handle.clone())
                .sensitivity(self.sensitivity)
                .denial_reason(reason.clone())
                .caller_program("merkle-agent");
                crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

                return Err(AppError::PolicyDenied(reason.as_str().to_owned()));
            }
            RevealAuthorization::Allow => {}
        }

        // 3. Load the secret from storage.
        let secret = ctx
            .storage
            .get_secret_by_handle(&self.handle)
            .await?
            .ok_or(AppError::NotFound)?;

        // 4. Decrypt the private blob from the current version.
        let blob = &secret
            .versions()
            .iter()
            .find(|v| v.is_active())
            .ok_or(AppError::NotFound)?
            .blob;

        let mut aad = blob.associated_data.clone();
        let mut cipher_with_tag = blob.ciphertext.clone();
        cipher_with_tag.extend_from_slice(&blob.aead_tag);

        let plaintext =
            ctx.crypto
                .aead_decrypt(&self.dek_bytes, &blob.nonce, &cipher_with_tag, &aad)?;
        aad.clear(); // defensive; aad is just the handle URI bytes

        // 6. Audit success (BUG-06: persist-then-advance atomically).
        let hmac_key = ctx.require_hmac_key().await?;
        let params = merkle_domain_audit_compliance::AppendParams::new(
            AuditOp::Reveal,
            AuditOutcome::Allow,
            self.namespace_id,
        )
        .handle(self.handle.clone())
        .sensitivity(self.sensitivity)
        .caller_program("merkle-agent");
        crate::commands::unseal_vault::audit_commit(ctx, params, &hmac_key).await?;

        info!(handle = %self.handle, "reveal_secret: plaintext decrypted");
        Ok(RevealSecretOutput { plaintext })
    }
}

/// Placeholder software-class device used when no companion is enrolled.
/// Terminal / desktop OOB channels accept any target device record.
fn software_placeholder_device() -> CompanionDevice {
    CompanionDevice {
        device_id: merkle_types::UuidV7::new(),
        ed25519_pubkey: [0u8; 32],
        x25519_pubkey: [0u8; 32],
        class: CompanionDeviceClass::Software,
        attestation_chain: Vec::new(),
        enrolled_at: Rfc3339Timestamp::now(),
        revoked_at: None,
    }
}
