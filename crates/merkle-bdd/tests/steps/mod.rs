//! Step-definition modules and [`MerkleWorld`] shared state.

pub mod given;
pub mod then;
pub mod when;

use std::sync::Arc;

use cucumber::World;
use merkle_adapter_crypto::RustCryptoAdapter;
use merkle_adapter_external_services::MockExternalServices;
use merkle_adapter_keychain::MockKeychainAdapter;
use merkle_adapter_oob::mock::MockOobNotifier;
use merkle_adapter_sqlite::SqliteStorage;
use merkle_application::AppContext;
use merkle_domain_identity::recovery_key::RecoveryPublicKey;
use merkle_domain_identity::{KeychainEntry, VaultIdentity};
use merkle_ports::Keychain as _;
use merkle_types::{AuditOp, AuditOutcome, Handle, NamespaceId, NamespaceLabel, Rfc3339Timestamp};

/// Constant master key stored in the mock keychain for unsealing in tests.
pub const MOCK_MASTER_KEY: [u8; 32] = [0xAAu8; 32];

/// Service + account used by the mock keychain for the master key.
pub const KEYCHAIN_SERVICE: &str = "dev.fapp.merkle";
pub const KEYCHAIN_ACCOUNT: &str = "master-v1";

/// Shared state threaded through every BDD scenario step.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, World)]
#[world(init = Self::new)]
pub struct MerkleWorld {
    /// Application context wiring all adapters together.
    pub app_ctx: Arc<AppContext>,

    /// Mock keychain — allows inspecting calls in `then` steps.
    pub keychain: Arc<MockKeychainAdapter>,

    /// Mock OOB notifier — pre-load resolutions per scenario.
    pub oob: Arc<MockOobNotifier>,

    /// Mock external services (SSH/HTTP).
    pub external: Arc<MockExternalServices>,

    // -----------------------------------------------------------------------
    // Per-scenario accumulated state
    // -----------------------------------------------------------------------
    /// The last audit op observed in a `then` assertion step.
    pub last_audit_op: Option<AuditOp>,

    /// The last audit outcome observed.
    pub last_audit_outcome: Option<AuditOutcome>,

    /// Denial reason from the last rejected operation.
    pub last_denial_reason: Option<String>,

    /// Last error string returned by an application command.
    pub last_error: Option<String>,

    /// The namespace label established by a `Given` step.
    pub session_namespace: Option<NamespaceLabel>,

    /// The namespace id established by a `Given` step.
    pub session_namespace_id: Option<NamespaceId>,

    /// 32-byte DEK used for the session namespace (plaintext in tests).
    pub session_dek: [u8; 32],

    /// The handle returned by the last successful put/rotate operation.
    pub last_handle: Option<Handle>,

    /// Plaintext returned by the last successful reveal.
    pub last_plaintext: Option<Vec<u8>>,

    /// The new version number from the last rotate.
    pub last_version_no: Option<u32>,

    /// Generic counter used to accumulate mutation counts in backup scenarios.
    pub mutation_counter: u32,

    /// Set to true when a rate-limit `given` step simulates the limit being hit.
    pub rate_limited: bool,

    /// Whether the slash command operator confirmation flag is set.
    /// Defaults to `true` (safe default for most reveal scenarios).
    pub op_slash_command: bool,

    /// Whether the OOB acknowledgment flag is set.
    /// Defaults to `false` (safe default for most reveal scenarios).
    pub op_oob_ack: bool,

    /// When `true`, the OobResolution payload has a null device_signature.
    /// Used by "oob_signature_missing" BDD scenarios to inject a synthetic failure.
    pub oob_signature_null: bool,

    /// When `true`, the OobResolution payload has an invalid device_signature.
    /// Used by "oob_signature_invalid" BDD scenarios to inject a synthetic failure.
    pub oob_signature_invalid: bool,

    /// The handle most recently passed to `when_mcp_vault_reveal`.
    /// Stored so `when_oob_acknowledged` can re-run the reveal after OOB ack.
    pub last_reveal_handle: Option<merkle_types::Handle>,

    /// HTTP status code from the last POST /v1/agent/init call (0 = not called).
    pub init_http_status: u16,

    /// Recovery key returned by the last init call.
    pub init_recovery_key: Option<String>,

    // -----------------------------------------------------------------------
    // JWT attestation state (ADR-0011 Amendment 6)
    // -----------------------------------------------------------------------
    /// Ed25519 signing key seed used for the enrolled attestation key.
    ///
    /// Set by `given_enrolled_jwt_attestation_key`. The verifier reads the
    /// corresponding public key from the mock keychain.
    pub jwt_signing_seed: Option<[u8; 32]>,

    /// Compact JWT string to pass as `signed_config_flag` in the next reveal.
    pub jwt_token: Option<String>,

    /// Key identifier for the JWT (`kid` claim).
    pub jwt_key_id: Option<String>,

    /// `ChallengeId` generated for the current JWT attestation round-trip.
    pub jwt_challenge_id: Option<merkle_types::ChallengeId>,

    // -----------------------------------------------------------------------
    // port_forward MCP result state (F12 / ADR-0023)
    // -----------------------------------------------------------------------
    /// Session id returned by the last successful port_forward call.
    pub port_forward_session_id: Option<String>,

    /// Local address bound by the last successful port_forward call.
    pub port_forward_local_addr: Option<String>,
}

impl MerkleWorld {
    async fn new() -> Self {
        // Spin up a fresh in-memory SQLite database.
        let storage = Arc::new(
            SqliteStorage::open("sqlite::memory:")
                .await
                .expect("in-memory sqlite failed"),
        );
        let keychain = Arc::new(MockKeychainAdapter::new());
        let crypto = Arc::new(RustCryptoAdapter::new());
        let oob = Arc::new(MockOobNotifier::new());
        let external = Arc::new(MockExternalServices::new());

        // Pre-seed the mock keychain with the master key so the unseal sequence
        // can retrieve it without requiring a real OS keychain.
        keychain
            .store(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, &MOCK_MASTER_KEY)
            .await
            .expect("keychain seed failed");
        // Seed the master-wrapped VRK so UnsealVaultCommand can AEAD-decrypt it
        // (modelling a vault that has already run InitVaultCommand).
        seed_master_wrapped_vrk(keychain.as_ref(), &MOCK_MASTER_KEY).await;

        // Enable OOB auto-approval by default so reveal scenarios that
        // trigger OOB succeed without needing pre-loaded resolutions.
        // Individual scenarios that test OOB denial will override this.
        oob.set_auto_approve(true);

        // Build a minimal VaultIdentity in Sealed state.
        let keychain_entry = KeychainEntry::for_master_key(1, Rfc3339Timestamp::now());
        let recovery_pubkey = RecoveryPublicKey::new(
            "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq".to_owned(),
            "SHA256:test=".to_owned(),
            Rfc3339Timestamp::now(),
        );
        let identity = VaultIdentity::new(keychain_entry, recovery_pubkey);

        let app_ctx = Arc::new(AppContext::new(
            storage.clone(),
            keychain.clone(),
            crypto,
            oob.clone(),
            external.clone(),
            identity,
        ));

        // Test DEK: 32 zeroed bytes (deterministic in tests).
        let session_dek = [0u8; 32];

        Self {
            app_ctx,
            keychain,
            oob,
            external,
            last_audit_op: None,
            last_audit_outcome: None,
            last_denial_reason: None,
            last_error: None,
            session_namespace: None,
            session_namespace_id: None,
            session_dek,
            last_handle: None,
            last_plaintext: None,
            last_version_no: None,
            mutation_counter: 0,
            rate_limited: false,
            op_slash_command: true,
            op_oob_ack: false,
            oob_signature_null: false,
            oob_signature_invalid: false,
            last_reveal_handle: None,
            init_http_status: 0,
            init_recovery_key: None,
            jwt_signing_seed: None,
            jwt_token: None,
            jwt_key_id: None,
            jwt_challenge_id: None,
            port_forward_session_id: None,
            port_forward_local_addr: None,
        }
    }

    // -----------------------------------------------------------------------
    // Helpers shared across step modules
    // -----------------------------------------------------------------------

    /// Run the standard unseal sequence using the pre-seeded mock keychain.
    ///
    /// No-op when the vault is already unsealed.
    pub async fn do_unseal(&self) {
        use merkle_application::commands::unseal_vault::UnsealVaultCommand;
        use merkle_domain_identity::UnsealPreconditions;
        use merkle_types::SecurityProfile;

        if self.app_ctx.is_unsealed().await {
            return;
        }
        let cmd = UnsealVaultCommand {
            preconditions: UnsealPreconditions {
                security_profile: SecurityProfile::Relaxed,
                mlock_succeeded: true,
                entropy_seeded: true,
                keychain_reachable: true,
            },
        };
        cmd.execute(&self.app_ctx)
            .await
            .expect("unseal must succeed in test setup");
    }

    /// Write a synthetic audit entry directly to storage.
    ///
    /// Used in BDD steps for commands that are scaffolded (not yet fully
    /// implemented) but whose audit contract must be verified by `then` steps.
    /// Uses a zeroed HMAC key — acceptable for tests.
    pub async fn write_synthetic_audit(&self, op: AuditOp, outcome: AuditOutcome) {
        use merkle_domain_audit_compliance::{AppendParams, AuditWriter};

        let hmac_key = [0u8; 32];
        let ns_id = self.session_namespace_id.unwrap_or_default();
        let params = AppendParams::new(op, outcome, ns_id).caller_program("merkle-bdd-synthetic");
        let mut log = self.app_ctx.audit_log.write().await;
        let Ok((entry, pinned)) = AuditWriter::append(&mut log, params, &hmac_key) else {
            return;
        };
        drop(log);
        let _ = self.app_ctx.storage.append_audit_entry(&entry).await;
        let _ = self.app_ctx.storage.update_pinned_head(&pinned).await;
    }

    /// Ensure the session namespace is bound in storage, creating it if needed.
    /// Returns the `NamespaceId`.
    pub async fn ensure_namespace(&self, label_str: &str) -> NamespaceId {
        use merkle_application::commands::bind_namespace::BindNamespaceCommand;
        use merkle_types::NamespaceLabel;

        let label: NamespaceLabel = label_str.parse().expect("valid namespace label");

        // Check if it already exists.
        if let Ok(Some(ns)) = self.app_ctx.storage.get_namespace_by_label(&label).await {
            return ns.id;
        }

        let cmd = BindNamespaceCommand {
            label: label.clone(),
            cwd_hash: None,
            dek_version: 1,
        };
        let out = cmd
            .execute(&self.app_ctx)
            .await
            .expect("bind namespace must succeed");
        out.namespace_id
    }
}

/// Wrap a deterministic VRK under `master_key` and store it where
/// `UnsealVaultCommand` expects it — mirroring the blob `InitVaultCommand` persists.
async fn seed_master_wrapped_vrk(
    keychain: &dyn merkle_ports::keychain::Keychain,
    master_key: &[u8; 32],
) {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use merkle_application::commands::init_vault::{KEYCHAIN_ACCOUNT_VRK_MASTER, VRK_MASTER_AAD};
    use merkle_ports::Crypto as _;

    let crypto = RustCryptoAdapter::new();
    let vrk = [0x11_u8; 32];
    let nonce = [0x22_u8; 24];
    let ciphertext = crypto
        .aead_encrypt(master_key, &nonce, &vrk, VRK_MASTER_AAD)
        .expect("wrap VRK under master key");
    let mut buf = Vec::with_capacity(nonce.len() + ciphertext.len());
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(&ciphertext);
    let payload = BASE64.encode(&buf).into_bytes();
    keychain
        .store(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT_VRK_MASTER, &payload)
        .await
        .expect("store master-wrapped VRK");
}
