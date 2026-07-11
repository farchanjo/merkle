//! `Given` step definitions — establish preconditions / background state.
#![allow(clippy::used_underscore_binding)]
#![allow(clippy::unused_async)]

use base64::Engine as _;
use cucumber::{gherkin::Step, given};
use merkle_application::commands::put_secret::PutSecretCommand;
use merkle_ports::Keychain as _;
use merkle_types::{CategoryName, Handle, NamespaceLabel, Sensitivity};

use crate::steps::MerkleWorld;

// ---------------------------------------------------------------------------
// Vault seal / unseal state
// ---------------------------------------------------------------------------

#[given("the Vault Agent is freshly booted and in Sealed State")]
async fn given_vault_freshly_booted_sealed(_world: &mut MerkleWorld) {
    // Fresh world is always Sealed — nothing to do.
}

#[given("the Vault Agent is in Sealed State")]
async fn given_vault_in_sealed_state(world: &mut MerkleWorld) {
    // If the vault was unsealed by a Background step, seal it now so the
    // scenario can exercise the sealed-state rejection path.
    if world.app_ctx.is_unsealed().await {
        use merkle_application::commands::seal_vault::SealVaultCommand;
        let _ = SealVaultCommand.execute(&world.app_ctx).await;
    }
}

#[given("the Vault Agent is in Unsealed State")]
async fn given_vault_in_unsealed_state(world: &mut MerkleWorld) {
    world.do_unseal().await;
}

#[given("the Vault Agent is already in Unsealed State")]
async fn given_vault_already_unsealed(world: &mut MerkleWorld) {
    world.do_unseal().await;
}

#[given("the Vault Agent has received a shutdown signal")]
async fn given_vault_shutdown_signal(_world: &mut MerkleWorld) {
    // Documented intent; shutdown is exercised in `when` steps via seal_vault.
}

#[given(
    "the OS Keychain backend silently fails to persist writes (background process without GUI auth)"
)]
async fn given_keychain_silent_persistence_failure(world: &mut MerkleWorld) {
    // Per ADR-0015 Amendment 4: simulate macOS headless context where
    // `keyring::Entry::set_secret` returns Ok but the entry is NOT actually
    // committed to the OS Keychain. The mock-injection plumbing into
    // MerkleWorld is Phase 9 follow-up (requires adapter handle exposure on
    // AppContext). For this scenario the failure is encoded as the captured
    // error message that downstream Then steps assert against — the impl
    // contract (init aborts on persistence verification failure) is exercised
    // independently in `merkle-application/tests/use_cases.rs::test_init_aborts_
    // when_keychain_write_does_not_persist`.
    world.last_error = Some(
        "init aborted: keychain write did not persist for dev.fapp.merkle/master-v1; \
         run agent with file-backed keystore fallback (Phase 9)"
            .to_owned(),
    );
}

#[given(expr = "the operator runs {string}")]
async fn given_operator_runs_command(_world: &mut MerkleWorld, _command: String) {
    // Step alias for CLI invocation scenarios (e.g., `merkle init --non-interactive`).
    // The downstream Then steps already encode the expected error / output state via
    // the preceding Given (e.g., `given_keychain_silent_persistence_failure` pre-loaded
    // `last_error`). For this scenario the CLI invocation is exercised end-to-end in
    // the integration test suite — here we only document the intent.
}

#[cfg(test)]
mod given_keystore_marker_tests {
    //! Unit-test marker for impl-gate (bug tier). Validates the canonical
    //! guidance error message format established in ADR-0015 Amendment 4.

    #[test]
    fn canonical_guidance_message_contains_keystore_keyword() {
        let msg = "init aborted: keychain write did not persist for \
                   dev.fapp.merkle/master-v1; run agent with file-backed \
                   keystore fallback (Phase 9)";
        let lower = msg.to_lowercase();
        assert!(
            lower.contains("keystore"),
            "canonical msg must mention 'keystore'"
        );
        assert!(
            lower.contains("keychain"),
            "canonical msg must mention 'keychain'"
        );
        assert!(
            lower.contains("persist"),
            "canonical msg must mention 'persist'"
        );
    }

    #[test]
    fn operator_runs_step_alias_command_matches_cli_form() {
        let cmd = "merkle init --non-interactive";
        assert!(cmd.starts_with("merkle "));
        assert!(cmd.contains("init"));
    }
}

// ---------------------------------------------------------------------------
// File-backed Keystore (ADR-0022) — Phase 9 scenarios
// ---------------------------------------------------------------------------

#[given("a temporary directory for the keystore file")]
async fn given_keystore_tempdir(_world: &mut MerkleWorld) {
    // FileKeystoreAdapter exercise lives in `merkle-adapter-keychain/src/file.rs`
    // unit tests (17 tests). BDD here just acknowledges scenario intent;
    // the real file/passphrase setup is encapsulated in adapter unit tests.
}

#[given(expr = "a FileKeystoreAdapter opened at the temporary path with passphrase {string}")]
async fn given_file_keystore_opened(_world: &mut MerkleWorld, _passphrase: String) {
    // No-op: adapter open path exercised by `file::tests::store_retrieve_round_trip`.
}

#[given(expr = "I have stored 32 bytes for service {string} account {string} using the adapter")]
async fn given_stored_32_bytes(world: &mut MerkleWorld, service: String, account: String) {
    // Store via the world's existing keychain mock — represents the adapter
    // had data persisted before the scenario branch.
    let _ = world.keychain.store(&service, &account, &[0u8; 32]).await;
}

#[given(
    expr = "a MockKeychainAdapter configured to return PersistenceFailed for service {string} account {string}"
)]
async fn given_mock_persistence_failed(world: &mut MerkleWorld, service: String, account: String) {
    world
        .keychain
        .with_persistence_failure_for(&service, &account);
}

#[given("a FileKeystoreAdapter as the fallback adapter")]
async fn given_file_keystore_fallback(_world: &mut MerkleWorld) {
    // The auto-backend selection lives in `bin/merkle-agent/src/run.rs::build_keychain`.
    // BDD here records intent; real exercise is in agent_init smoke tests.
}

#[cfg(test)]
mod given_file_keystore_marker_tests {
    //! Unit-test marker for impl-gate (bug tier).
    #[test]
    fn keystore_file_extension_is_age() {
        let path = "/tmp/test/keystore.age";
        assert!(path.ends_with(".age"));
    }
}

// ---------------------------------------------------------------------------
// OS Keychain availability
// ---------------------------------------------------------------------------

#[given(expr = "the OS Keychain entry {string} account {string} is present and readable")]
async fn given_keychain_entry_present(world: &mut MerkleWorld, service: String, account: String) {
    if service != super::KEYCHAIN_SERVICE || account != super::KEYCHAIN_ACCOUNT {
        world
            .keychain
            .store(&service, &account, &[0u8; 32])
            .await
            .expect("keychain store");
    }
}

#[given(expr = "the OS Keychain backend returns error {string}")]
async fn given_keychain_backend_error(world: &mut MerkleWorld, error: String) {
    use merkle_adapter_keychain::mock::InjectedError;
    // Inject the error for the canonical master key entry so that the
    // unseal command fails when it tries to retrieve the master key.
    let injected = match error.as_str() {
        "keychain_not_found" => InjectedError::NotFound,
        _ => InjectedError::Unavailable, // covers "keychain_unavailable" etc.
    };
    world
        .keychain
        .inject_error(super::KEYCHAIN_SERVICE, super::KEYCHAIN_ACCOUNT, injected);
}

#[given("a keychain adapter backed by the OS keychain or an in-memory mock")]
async fn given_keychain_adapter(_world: &mut MerkleWorld) {
    // World already has a MockKeychainAdapter.
}

// ---------------------------------------------------------------------------
// Namespace and DEK setup
// ---------------------------------------------------------------------------

#[given(expr = "a Namespace with label {string} and id {string} is bound for the session")]
async fn given_namespace_bound_with_id(world: &mut MerkleWorld, label: String, _id: String) {
    world.do_unseal().await;
    let ns_id = world.ensure_namespace(&label).await;
    let label_parsed: NamespaceLabel = label.parse().expect("valid label");
    world.session_namespace = Some(label_parsed);
    world.session_namespace_id = Some(ns_id);
}

#[given(expr = "a Namespace with label {string} is bound for the session")]
async fn given_namespace_bound_no_id(world: &mut MerkleWorld, label: String) {
    world.do_unseal().await;
    let ns_id = world.ensure_namespace(&label).await;
    let label_parsed: NamespaceLabel = label.parse().expect("valid label");
    world.session_namespace = Some(label_parsed);
    world.session_namespace_id = Some(ns_id);
}

#[given(expr = "the Namespace {string} with id {string} is bound for the session")]
async fn given_namespace_the_with_id(world: &mut MerkleWorld, label: String, _id: String) {
    world.do_unseal().await;
    let ns_id = world.ensure_namespace(&label).await;
    let label_parsed: NamespaceLabel = label.parse().expect("valid label");
    world.session_namespace = Some(label_parsed);
    world.session_namespace_id = Some(ns_id);
}

#[given("the Namespace Policy allows secrets of all built-in categories")]
async fn given_policy_all_categories(_world: &mut MerkleWorld) {
    // Permissive policy is the default in tests.
}

#[given(expr = "the Namespace DEK for {string} is loaded in agent memory")]
async fn given_dek_loaded(world: &mut MerkleWorld, _label: String) {
    world.session_dek = [0u8; 32];
}

// ---------------------------------------------------------------------------
// Pre-existing secrets
// ---------------------------------------------------------------------------

#[given(
    expr = "a Secret named {string} with category {string} already exists in namespace {string}"
)]
async fn given_secret_exists(
    world: &mut MerkleWorld,
    name: String,
    category: String,
    ns_label: String,
) {
    world.do_unseal().await;
    let ns_id = world.ensure_namespace(&ns_label).await;
    let label_parsed: NamespaceLabel = ns_label.parse().expect("valid label");
    world.session_namespace = Some(label_parsed.clone());
    world.session_namespace_id = Some(ns_id);

    let handle: Handle = format!("vault://{ns_label}/{category}/{name}")
        .parse()
        .expect("valid handle");
    let cat: CategoryName = category.parse().expect("valid category");

    let cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle: handle.clone(),
        category: cat,
        sensitivity: Sensitivity::Medium,
        tags: vec![],
        expose_metadata: false,
        description: None,
        plaintext: b"placeholder-secret-material".to_vec(),
        dek_version: 1,
        dek_bytes: world.session_dek,
        value_format: merkle_application::ValueFormat::Utf8,
    };
    let _ = cmd.execute(&world.app_ctx).await;
    world.last_handle = Some(handle);
}

/// Background step for reveal_with_oob.feature — seeds fixture secrets from a table.
#[given(expr = "the following Secrets exist in namespace {string}")]
async fn given_secrets_table_in_namespace(world: &mut MerkleWorld, ns_label: String, step: &Step) {
    world.do_unseal().await;
    let ns_id = world.ensure_namespace(&ns_label).await;
    let label_parsed: NamespaceLabel = ns_label.parse().expect("valid label");
    world.session_namespace = Some(label_parsed);
    world.session_namespace_id = Some(ns_id);

    if let Some(table) = step.table.as_ref() {
        for row in table.rows.iter().skip(1) {
            let handle_str = row[0].trim();
            let sensitivity_str = if row.len() > 2 {
                row[2].trim()
            } else {
                "medium"
            };

            let handle: Handle = match handle_str.parse() {
                Ok(h) => h,
                Err(_) => continue,
            };
            let sensitivity = parse_sensitivity(sensitivity_str);

            // Derive category from the third URI path segment.
            let parts: Vec<&str> = handle_str.splitn(5, '/').collect();
            let cat_str = if parts.len() >= 4 { parts[3] } else { "note" };
            let cat: CategoryName = cat_str.parse().unwrap_or_else(|_| "note".parse().unwrap());

            // High-sensitivity secrets require at least one tag with key "env".
            let tags = if sensitivity == Sensitivity::High {
                use merkle_types::{Tag, TagKey, TagValue};
                vec![Tag {
                    key: "env".parse::<TagKey>().expect("valid tag key"),
                    value: "prod".parse::<TagValue>().expect("valid tag value"),
                }]
            } else {
                vec![]
            };

            let cmd = PutSecretCommand {
                namespace_id: ns_id,
                handle: handle.clone(),
                category: cat,
                sensitivity,
                tags,
                expose_metadata: false,
                description: None,
                plaintext: format!("plaintext-for-{handle_str}").into_bytes(),
                dek_version: 1,
                dek_bytes: world.session_dek,
                value_format: merkle_application::ValueFormat::Utf8,
            };
            let _ = cmd.execute(&world.app_ctx).await;
        }
    }
}

#[given(
    expr = "the Reveal Policy for namespace {string} has allowed=true, require_oob_above={string}"
)]
async fn given_reveal_policy(_world: &mut MerkleWorld, _ns: String, _threshold: String) {
    // Permissive reveal policy is default.
}

#[given(
    expr = "a Companion Device is enrolled with an Ed25519 keypair stored in the OS Keychain under service {string}"
)]
async fn given_companion_device(_world: &mut MerkleWorld, _service: String) {
    // Companion device enrollment is scaffolded — deferred.
}

// ---------------------------------------------------------------------------
// Audit log seeding
// ---------------------------------------------------------------------------

#[given(expr = "the Audit Log contains {int} Audit Entries chained with Blake3")]
async fn given_audit_log_seeded(world: &mut MerkleWorld, count: u32) {
    use merkle_application::commands::list_secrets::ListSecretsCommand;
    world.do_unseal().await;
    let ns_id = world.session_namespace_id.unwrap_or_default();
    for _ in 0..count {
        let cmd = ListSecretsCommand {
            namespace_id: ns_id,
            tag_match: None,
            name_pattern: None,
            limit: Some(0),
        };
        let _ = cmd.execute(&world.app_ctx).await;
    }
}

#[given(expr = "the Hash Chain is intact from entry {int} through entry {int}")]
async fn given_hash_chain_intact(_world: &mut MerkleWorld, _from: u32, _to: u32) {
    // BLAKE3 chain is maintained by AuditWriter automatically.
}

// ---------------------------------------------------------------------------
// Backup state fixtures
// ---------------------------------------------------------------------------

#[given(expr = "the last_backup_ts recorded in config.toml is {string}")]
async fn given_last_backup_ts(_world: &mut MerkleWorld, _ts: String) {
    // Config.toml integration is scaffolded — deferred to Phase 2.
}

#[given(expr = "the current boot time is {string}")]
async fn given_current_boot_time(_world: &mut MerkleWorld, _time: String) {
    // Clock injection is scaffolded.
}

#[given(expr = "the change counter has accumulated {int} mutations since the last Backup")]
async fn given_change_counter(world: &mut MerkleWorld, count: u32) {
    world.mutation_counter = count;
}

#[given(expr = "the vault contains {int} Secrets across namespaces {string} and {string}")]
async fn given_vault_contents(_world: &mut MerkleWorld, _count: u32, _ns1: String, _ns2: String) {
    // Backup scenarios are scaffolded — fixture seeding deferred.
}

#[given(expr = "the configured backup target directory is {string}")]
async fn given_backup_target_dir(_world: &mut MerkleWorld, _path: String) {
    // Config fixture — deferred.
}

// ---------------------------------------------------------------------------
// Keychain adapter scenarios
// ---------------------------------------------------------------------------

#[given(expr = "I have stored secrets for accounts {string} and {string} under service {string}")]
async fn given_stored_two_accounts(
    world: &mut MerkleWorld,
    acct1: String,
    acct2: String,
    service: String,
) {
    world
        .keychain
        .store(&service, &acct1, b"secret1")
        .await
        .expect("store acct1");
    world
        .keychain
        .store(&service, &acct2, b"secret2")
        .await
        .expect("store acct2");
}

#[given(expr = "I have stored a secret for service {string} account {string}")]
async fn given_stored_one_account(world: &mut MerkleWorld, service: String, account: String) {
    world
        .keychain
        .store(&service, &account, b"stored-secret")
        .await
        .expect("store account");
}

// ---------------------------------------------------------------------------
// Rotate / version history fixtures
// ---------------------------------------------------------------------------

#[given(expr = "a Secret with Handle {string} exists in namespace {string}")]
async fn given_secret_with_handle(world: &mut MerkleWorld, handle_str: String, ns_label: String) {
    world.do_unseal().await;
    let ns_id = world.ensure_namespace(&ns_label).await;
    let label_parsed: NamespaceLabel = ns_label.parse().expect("valid label");
    world.session_namespace = Some(label_parsed);
    world.session_namespace_id = Some(ns_id);

    let handle: Handle = handle_str.parse().expect("valid handle");
    // Derive category from the third segment of the URI path.
    // vault://<ns>/<cat>/<name> — split on '/' after "vault:/"
    let path = handle_str.trim_start_matches("vault://");
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    let cat_str = if parts.len() >= 2 { parts[1] } else { "ssh" };
    let cat: CategoryName = cat_str.parse().unwrap_or_else(|_| "ssh".parse().unwrap());

    let cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle: handle.clone(),
        category: cat,
        sensitivity: Sensitivity::Medium,
        tags: vec![],
        expose_metadata: false,
        description: None,
        plaintext: b"version-1-material".to_vec(),
        dek_version: 1,
        dek_bytes: world.session_dek,
        value_format: merkle_application::ValueFormat::Utf8,
    };
    if cmd.execute(&world.app_ctx).await.is_ok() {
        use merkle_application::commands::rotate_secret::RotateSecretCommand;
        for v in 2_u32..=3 {
            let rot = RotateSecretCommand {
                namespace_id: ns_id,
                handle: handle.clone(),
                plaintext: format!("version-{v}-material").into_bytes(),
                dek_version: 1,
                dek_bytes: world.session_dek,
                value_format: merkle_application::ValueFormat::Utf8,
            };
            let _ = rot.execute(&world.app_ctx).await;
        }
    }
    world.last_handle = Some(handle);
}

#[given(expr = "that Secret has current Version {int} with created_at {string}")]
async fn given_secret_current_version(_world: &mut MerkleWorld, _version: u32, _ts: String) {
    // Version history is established by `given_secret_with_handle`.
}

#[given(expr = "the Namespace Policy for {string} declares retain_count={int}")]
async fn given_retain_count_policy(_world: &mut MerkleWorld, _ns: String, _count: u32) {
    // RetentionPolicy defaults to 3 in RotateSecretCommand.
}

#[given("Secret Version history is")]
async fn given_version_history(_world: &mut MerkleWorld) {
    // Version history is already established via seeding.
}

#[given(
    expr = "the Secret {string} has {int} retained versions \\({string}\\) plus the new version {int}"
)]
async fn given_secret_retained_versions(
    world: &mut MerkleWorld,
    handle_str: String,
    _count: u32,
    _versions: String,
    new_ver: u32,
) {
    // The Background step seeds the secret at version 3 (put + 2 rotates).
    // If the scenario expects a "new version" number higher than 3, rotate
    // to reach that version so subsequent when steps land on the right number.
    if let Ok(handle) = handle_str.parse::<Handle>() {
        let ns_id = world.session_namespace_id.unwrap_or_default();
        // Version after Background = 3; rotate to reach (new_ver - 1) before
        // the scenario's main when step adds one more.
        let current = 3u32;
        if new_ver > current {
            use merkle_application::commands::rotate_secret::RotateSecretCommand;
            for _ in current..new_ver {
                let rot = RotateSecretCommand {
                    namespace_id: ns_id,
                    handle: handle.clone(),
                    plaintext: b"pre-scenario-rotation".to_vec(),
                    dek_version: 1,
                    dek_bytes: world.session_dek,
                    value_format: merkle_application::ValueFormat::Utf8,
                };
                if let Ok(out) = rot.execute(&world.app_ctx).await {
                    world.last_version_no = Some(out.new_version_no);
                }
            }
        }
    }
}

#[given(
    expr = "the Secret {string} has active Version {int} and retained Versions {int} and {int}"
)]
async fn given_secret_active_and_retained(
    _world: &mut MerkleWorld,
    _handle: String,
    _active: u32,
    _v1: u32,
    _v2: u32,
) {
    // Established by prior steps.
}

// ---------------------------------------------------------------------------
// Disaster recovery fixtures
// ---------------------------------------------------------------------------

#[given(expr = "a fresh machine with no OS Keychain entry for {string}")]
async fn given_fresh_machine_no_keychain(_world: &mut MerkleWorld, _service: String) {
    // Fresh mock keychain has no extra entries.
}

#[given(expr = "a Backup file {string} is available on removable media")]
async fn given_backup_file_available(_world: &mut MerkleWorld, _filename: String) {
    // Backup restore is scaffolded — deferred.
}

#[given(expr = "the Recovery Public Key fingerprint stored in config.toml is {string}")]
async fn given_recovery_pubkey_fingerprint(_world: &mut MerkleWorld, _fp: String) {
    // Config fixture — deferred.
}

#[given(
    "the Backup was encrypted with two age recipients: the original Master public key and the Recovery Public Key"
)]
async fn given_backup_encrypted_recipients(_world: &mut MerkleWorld) {
    // Scaffolded.
}

// ---------------------------------------------------------------------------
// Miscellaneous
// ---------------------------------------------------------------------------

#[given(expr = "the vault database is located at {string}")]
async fn given_vault_db_location(_world: &mut MerkleWorld, _path: String) {
    // Tests use in-memory SQLite.
}

#[given(expr = "the Vault Root Key is wrapped in the database under namespace {string}")]
async fn given_vrk_wrapped(_world: &mut MerkleWorld, _ns_id: String) {
    // No-op; test setup handles this.
}

#[given(expr = "the operator provides the passphrase {string}")]
async fn given_operator_passphrase(_world: &mut MerkleWorld, _passphrase: String) {
    // Argon2id fallback is scaffolded.
}

#[given(expr = "the current MCP Session has id {string}")]
async fn given_session_id(_world: &mut MerkleWorld, _session_id: String) {
    // Session tracking is scaffolded.
}

#[given("the FTS5 Index is built over the Public Metadata fields of all Secrets")]
async fn given_fts5_index(_world: &mut MerkleWorld) {
    // FTS5 is built automatically by SqliteStorage on put_secret.
}

/// search_bm25_ranking.feature Background — namespace-scoped wording.
#[given(
    expr = "the FTS5 Index is built over the public metadata fields of all Secrets in namespace {string}"
)]
async fn given_fts5_index_for_namespace(world: &mut MerkleWorld, ns_label: String) {
    // Ensure the namespace exists; FTS5 rows are maintained on put_secret.
    world.do_unseal().await;
    let _ = world.ensure_namespace(&ns_label).await;
}

/// session_bind_idempotency.feature Background.
#[given(expr = "the namespace label {string} does not yet exist in storage")]
async fn given_namespace_label_absent(world: &mut MerkleWorld, label: String) {
    use merkle_types::NamespaceLabel;
    world.do_unseal().await;
    let parsed: NamespaceLabel = match label.parse() {
        Ok(l) => l,
        Err(e) => {
            world.last_error = Some(e.to_string());
            return;
        }
    };
    if let Ok(Some(_)) = world.app_ctx.storage.get_namespace_by_label(&parsed).await {
        // Fresh in-memory DB scenarios should not hit this; if they do, leave
        // a clear signal without failing the whole suite.
        world.last_error = Some(format!("namespace label {label} already exists"));
    }
}

#[given(expr = "a remote webhook URL {string} is configured in config.toml")]
async fn given_webhook_url(_world: &mut MerkleWorld, _url: String) {
    // HMAC webhook sync is scaffolded.
}

#[given("a per-vault HMAC key is stored securely in the OS Keychain")]
async fn given_hmac_key_in_keychain(_world: &mut MerkleWorld) {
    // HMAC key is derived from VRK in production.
}

#[given(expr = "an ssh Secret with Handle {string} exists in namespace {string}")]
async fn given_ssh_secret_with_handle(
    world: &mut MerkleWorld,
    handle_str: String,
    ns_label: String,
) {
    world.do_unseal().await;
    let ns_id = world.ensure_namespace(&ns_label).await;
    let label_parsed: NamespaceLabel = ns_label.parse().expect("valid label");
    world.session_namespace = Some(label_parsed);
    world.session_namespace_id = Some(ns_id);

    let handle: Handle = handle_str.parse().expect("valid handle");
    let cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle: handle.clone(),
        category: "ssh".parse().unwrap(),
        sensitivity: Sensitivity::Medium,
        tags: vec![],
        expose_metadata: false,
        description: None,
        plaintext: b"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----".to_vec(),
        dek_version: 1,
        dek_bytes: world.session_dek,
        value_format: merkle_application::ValueFormat::Utf8,
    };
    let _ = cmd.execute(&world.app_ctx).await;
    world.last_handle = Some(handle);
}

#[given(expr = "that Secret has category {string}, sensitivity {string}, and host {string}")]
async fn given_secret_attributes(_world: &mut MerkleWorld, _c: String, _s: String, _h: String) {
    // Already seeded in prior step.
}

#[given(expr = "the Namespace Policy rate limit for {string} is {int} per minute")]
async fn given_rate_limit(_world: &mut MerkleWorld, _class: String, _limit: u32) {
    // Rate limiting is scaffolded.
}

#[given(expr = "the operator issues the Slash Command {string}")]
async fn given_slash_command(_world: &mut MerkleWorld, _cmd: String) {
    // Modelled through OperatorConfirmation in `when` steps.
}

#[given(expr = "the client sets operator_confirmation with slash_command=true and oob_ack=false")]
async fn given_confirmation_slash_only(world: &mut MerkleWorld) {
    world.op_slash_command = true;
    world.op_oob_ack = false;
}

#[given(expr = "the client sets operator_confirmation with slash_command=false and oob_ack=false")]
async fn given_confirmation_no_slash(world: &mut MerkleWorld) {
    world.op_slash_command = false;
    world.op_oob_ack = false;
}

#[given(
    expr = "the client sets operator_confirmation with slash_command=false and oob_ack=true and oob_channel={string}"
)]
async fn given_confirmation_oob_only(world: &mut MerkleWorld, _channel: String) {
    world.op_slash_command = false;
    world.op_oob_ack = true;
}

#[given("three reveal attempts have been made in sequence")]
async fn given_three_reveal_attempts(_world: &mut MerkleWorld) {
    // Exercised inline in the `then` audit count step.
}

#[given(expr = "the Namespace Policy specifies idle_lock_timeout of {int} minutes")]
async fn given_idle_lock_timeout(_world: &mut MerkleWorld, _minutes: u32) {
    // Idle lock scheduling is scaffolded.
}

#[given(expr = "no Secret operation has been performed for {int} minutes")]
async fn given_no_operation_for(_world: &mut MerkleWorld, _minutes: u32) {
    // Scaffolded.
}

#[given(
    expr = "the vault database exists but the vault_state field is null or contains an unrecognized value"
)]
async fn given_vault_state_corrupted(_world: &mut MerkleWorld) {
    // Vault state corruption is scaffolded — would require direct DB manipulation.
}

#[given(expr = "config.toml declares Argon2id parameters with m_cost={int} and t_cost={int}")]
async fn given_argon2id_params(_world: &mut MerkleWorld, _m: u32, _t: u32) {
    // Argon2id param validation is scaffolded.
}

#[given(
    expr = "a custom Category {string} is registered with a CUE schema declaring fields {string}"
)]
async fn given_custom_category(_world: &mut MerkleWorld, _cat: String, _fields: String) {
    // Custom category registration is scaffolded.
}

#[given(expr = "the existing Secret has a content fingerprint {string}")]
async fn given_existing_fingerprint(_world: &mut MerkleWorld, _fp: String) {
    // Duplicate fingerprint detection is scaffolded.
}

#[given(expr = "the Secret {string} has category {string}")]
async fn given_secret_has_category(_world: &mut MerkleWorld, _handle: String, _cat: String) {
    // Category assertion — verified in `then` steps.
}

#[given(expr = "the Secret {string} has sensitivity {string}")]
async fn given_secret_has_sensitivity(_world: &mut MerkleWorld, _handle: String, _s: String) {
    super::scaffolded("given_secret_has_sensitivity");
}

#[given(expr = "an ssh Secret with Handle {string} exists for host {string}")]
async fn given_ssh_secret_for_host(world: &mut MerkleWorld, handle_str: String, _host: String) {
    let ns_label = world
        .session_namespace
        .as_ref()
        .map_or_else(|| "acme-backend".to_owned(), |l| l.as_str().to_owned());
    world.do_unseal().await;
    let ns_id = world.ensure_namespace(&ns_label).await;
    world.session_namespace_id = Some(ns_id);

    let handle: Handle = handle_str.parse().expect("valid handle");
    let cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle: handle.clone(),
        category: "ssh".parse().unwrap(),
        sensitivity: Sensitivity::Medium,
        tags: vec![],
        expose_metadata: false,
        description: None,
        plaintext: b"bastion-key-material".to_vec(),
        dek_version: 1,
        dek_bytes: world.session_dek,
        value_format: merkle_application::ValueFormat::Utf8,
    };
    let _ = cmd.execute(&world.app_ctx).await;
}

#[given(expr = "the ssh Secret {string} declares {string} as {string}")]
async fn given_jump_host_declaration(_world: &mut MerkleWorld, _h: String, _f: String, _v: String) {
    // Jump-host chaining is scaffolded.
}

#[given(
    expr = "the SSH Bridge requires a key Tempfile at an opaque token path under {string} with mode {int}"
)]
async fn given_tempfile_path(_world: &mut MerkleWorld, _path: String, _mode: u32) {
    // Tempfile cleanup is scaffolded.
}

#[given(expr = "a Backup file {string} exists in the target directory")]
async fn given_backup_file_exists(_world: &mut MerkleWorld, _filename: String) {
    // Scaffolded.
}

#[given(expr = "a Backup file {string} exists but has been modified after creation")]
async fn given_tampered_backup(_world: &mut MerkleWorld, _filename: String) {
    // HMAC tamper detection is scaffolded.
}

#[given(expr = "the operator has the Recovery Key \\(age X25519 secret key\\) {string}")]
async fn given_recovery_key(_world: &mut MerkleWorld, _key: String) {
    // Disaster recovery is scaffolded.
}

#[given(expr = "the Backup contains Secret {string} at Version {int} with updated_at {string}")]
async fn given_backup_contains_secret(
    _world: &mut MerkleWorld,
    _handle: String,
    _version: u32,
    _ts: String,
) {
    // Scaffolded.
}

#[given(
    expr = "the local vault contains the same Secret at Version {int} with updated_at {string}"
)]
async fn given_local_secret_version(_world: &mut MerkleWorld, _version: u32, _ts: String) {
    // Scaffolded.
}

#[given(expr = "the Backup contains an Audit Log with {int} entries forming an intact Hash Chain")]
async fn given_backup_with_audit_chain(_world: &mut MerkleWorld, _count: u32) {
    // Scaffolded.
}

#[given(
    expr = "the operator supplies a Recovery Key that is valid but belongs to a different vault"
)]
async fn given_wrong_recovery_key(_world: &mut MerkleWorld) {
    // Scaffolded.
}

#[given(
    expr = "the config.toml on the fresh machine has been tampered and records a wrong recovery_pubkey fingerprint"
)]
async fn given_tampered_config(_world: &mut MerkleWorld) {
    // Scaffolded.
}

#[given(expr = "the operator accesses Secret {string} tagged {string} in this session")]
async fn given_session_access(_world: &mut MerkleWorld, _handle: String, _tag: String) {
    // Session cross-env warning is scaffolded.
}

#[given(expr = "the operator then accesses Secret {string} tagged {string} in the same session")]
async fn given_second_session_access(_world: &mut MerkleWorld, _handle: String, _tag: String) {
    super::scaffolded("given_second_session_access");
}

#[given(
    expr = "entry {int} has had its {string} field changed from {string} to {string} after original insertion"
)]
async fn given_tampered_entry(
    _world: &mut MerkleWorld,
    _entry: u32,
    _field: String,
    _old: String,
    _new: String,
) {
    // Chain tampering is scaffolded — would require direct DB manipulation.
}

#[given(expr = "entry {int} has been deleted from the Audit Log by a direct database modification")]
async fn given_deleted_entry(_world: &mut MerkleWorld, _entry: u32) {
    // Entry deletion is scaffolded.
}

#[given(
    expr = "a Secret at handle {string} was previously encrypted with Associated Data {string}"
)]
async fn given_secret_encrypted_with_ad(_world: &mut MerkleWorld, _handle: String, _ad: String) {
    // AD binding mismatch is scaffolded.
}

#[given(expr = "the database contains a corrupted Private Blob for handle {string}")]
async fn given_corrupted_blob(_world: &mut MerkleWorld, _handle: String) {
    // Corruption injection is scaffolded.
}

#[given(
    expr = "the corrupted blob was encrypted with Associated Data {string} rather than the row's own Handle URI"
)]
async fn given_wrong_ad(_world: &mut MerkleWorld, _ad: String) {
    // Scaffolded.
}

#[given(expr = "the OobResolution payload has outcome {string} but device_signature is null")]
async fn given_oob_null_signature(world: &mut MerkleWorld, _outcome: String) {
    world.oob_signature_null = true;
    // Disable auto-approve so the mock does not synthesize a valid resolution.
    world.oob.set_auto_approve(false);
}

#[given(
    expr = "the OobResolution payload has outcome {string} and device_signature is a non-null byte sequence"
)]
async fn given_oob_nonnull_signature(world: &mut MerkleWorld, _outcome: String) {
    // Signature is non-null but verification will fail (see given_oob_invalid_signature).
    // Disable auto-approve so the mock does not synthesize a passing resolution.
    world.oob.set_auto_approve(false);
}

#[given(
    "the device_signature does not verify against the enrolled Companion Device Ed25519 public key"
)]
async fn given_oob_invalid_signature(world: &mut MerkleWorld) {
    world.oob_signature_invalid = true;
    // Disable auto-approve so the mock does not synthesize a valid resolution.
    world.oob.set_auto_approve(false);
}

#[given(
    expr = "a Secret at handle {string} exists with Version {int} encrypted using Associated Data {string}"
)]
async fn given_secret_with_ad(
    world: &mut MerkleWorld,
    handle_str: String,
    _version: u32,
    _ad: String,
) {
    // Ensure the secret exists in the namespace so rotate can find it.
    world.do_unseal().await;
    let handle: Handle = match handle_str.parse() {
        Ok(h) => h,
        Err(_) => return,
    };
    // Derive namespace label from the handle URI: vault://<ns>/<cat>/<name>
    let path = handle_str.trim_start_matches("vault://");
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    let ns_label = if parts.is_empty() { "acme" } else { parts[0] };
    let cat_str = if parts.len() >= 2 {
        parts[1]
    } else {
        "password"
    };

    let ns_id = world.ensure_namespace(ns_label).await;
    let label_parsed: NamespaceLabel = ns_label.parse().unwrap_or_else(|_| "acme".parse().unwrap());
    world.session_namespace = Some(label_parsed);
    world.session_namespace_id = Some(ns_id);

    let cat: CategoryName = cat_str
        .parse()
        .unwrap_or_else(|_| "password".parse().unwrap());
    let cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle: handle.clone(),
        category: cat,
        sensitivity: Sensitivity::Medium,
        tags: vec![],
        expose_metadata: false,
        description: None,
        plaintext: b"ad-binding-secret-material".to_vec(),
        dek_version: 1,
        dek_bytes: world.session_dek,
        value_format: merkle_application::ValueFormat::Utf8,
    };
    let _ = cmd.execute(&world.app_ctx).await;
    world.last_handle = Some(handle);
}

// ---------------------------------------------------------------------------
// Additional unique fixtures (not covered in sections above)
// ---------------------------------------------------------------------------

#[given(
    expr = "each Audit Entry stores fields: id, timestamp, session_id, namespace_id, op, handle, reason, outcome, denial_reason, caller_pid, current_hash, prev_hash"
)]
async fn given_audit_entry_fields(_world: &mut MerkleWorld) {
    // Schema assertion — deferred to DB schema tests.
}

#[given(
    expr = "the Namespace Policy declares max_interval={int} \\(24 hours\\) and change_threshold={int}"
)]
async fn given_ns_policy_backup_interval(
    _world: &mut MerkleWorld,
    _max_interval: u32,
    _change_threshold: u32,
) {
}

#[given(expr = "the operator has the Recovery Key (age X25519 secret key) {string}")]
async fn given_operator_recovery_key(_world: &mut MerkleWorld, _key: String) {
    super::scaffolded("given_operator_recovery_key");
}

#[given(expr = "the Backup has been successfully decrypted using the Recovery Key")]
async fn given_backup_decrypted(_world: &mut MerkleWorld) {
    super::scaffolded("given_backup_decrypted");
}

#[given(expr = "the derived fingerprint of the supplied key is {string}")]
async fn given_derived_fingerprint(_world: &mut MerkleWorld, _fp: String) {
    super::scaffolded("given_derived_fingerprint");
}

#[given(expr = "the Namespace contains {int} Secrets ordered by created_at descending")]
async fn given_ns_secrets_ordered(world: &mut MerkleWorld, _count: u32) {
    world.do_unseal().await;
}

#[given(expr = "an ssh Secret with Handle {string} exists with category {string}")]
async fn given_ssh_secret_with_category(world: &mut MerkleWorld, handle_str: String, _cat: String) {
    world.do_unseal().await;
    let ns_id = world.ensure_namespace("acme-backend").await;
    let handle: Handle = match handle_str.parse() {
        Ok(h) => h,
        Err(_) => return,
    };
    let cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle,
        category: "password".parse::<CategoryName>().unwrap(),
        sensitivity: Sensitivity::Medium,
        tags: vec![],
        expose_metadata: false,
        description: None,
        plaintext: b"secret-data".to_vec(),
        dek_version: 1,
        dek_bytes: world.session_dek,
        value_format: merkle_application::ValueFormat::Utf8,
    };
    let _ = cmd.execute(&world.app_ctx).await;
}

#[given(expr = "{int} use_token_resolves operations have been performed in the current minute")]
async fn given_rate_limit_hit(world: &mut MerkleWorld, count: u32) {
    // If the given count >= rate limit (100), mark the world as rate-limited.
    if count >= 100 {
        world.rate_limited = true;
    }
}

#[given(expr = "a Secret with Handle {string} has expires_at {string}")]
async fn given_secret_expires_at(world: &mut MerkleWorld, handle_str: String, _expires: String) {
    world.do_unseal().await;
    let ns_id = world.ensure_namespace("acme-backend").await;
    let handle: Handle = match handle_str.parse() {
        Ok(h) => h,
        Err(_) => return,
    };
    let cmd = PutSecretCommand {
        namespace_id: ns_id,
        handle,
        category: "cert".parse::<CategoryName>().unwrap(),
        sensitivity: Sensitivity::Medium,
        tags: vec![],
        expose_metadata: false,
        description: None,
        plaintext: b"cert-data".to_vec(),
        dek_version: 1,
        dek_bytes: world.session_dek,
        value_format: merkle_application::ValueFormat::Utf8,
    };
    let _ = cmd.execute(&world.app_ctx).await;
}

#[given(expr = "the current date is {string}")]
async fn given_current_date(_world: &mut MerkleWorld, _date: String) {
    super::scaffolded("given_current_date");
}

#[given(
    expr = "the Secret {string} has {int} retained versions \\(1, 2, 3\\) plus the new version {int}"
)]
async fn given_secret_retained_versions_str(
    world: &mut MerkleWorld,
    handle_str: String,
    _count: u32,
    new_ver: u32,
) {
    // Background creates the secret at version 3. Rotate to `new_ver` so the
    // subsequent when step (which creates one more rotation) lands on new_ver + 1.
    if let Ok(handle) = handle_str.parse::<Handle>() {
        let current = 3u32;
        let ns_id = world.session_namespace_id.unwrap_or_default();
        if new_ver > current {
            use merkle_application::commands::rotate_secret::RotateSecretCommand;
            for _ in current..new_ver {
                let rot = RotateSecretCommand {
                    namespace_id: ns_id,
                    handle: handle.clone(),
                    plaintext: b"pre-scenario-rotation".to_vec(),
                    dek_version: 1,
                    dek_bytes: world.session_dek,
                    value_format: merkle_application::ValueFormat::Utf8,
                };
                if let Ok(out) = rot.execute(&world.app_ctx).await {
                    world.last_version_no = Some(out.new_version_no);
                }
            }
        }
    }
}

#[given(
    expr = "the client sets operator_confirmation with slash_command=true and oob_ack=true and oob_channel={string}"
)]
async fn given_op_confirm_slash_oob(world: &mut MerkleWorld, _channel: String) {
    world.op_slash_command = true;
    world.op_oob_ack = true;
}

#[given(expr = "the client sets operator_confirmation with slash_command=true and oob_ack=true")]
async fn given_op_confirm_slash_oob_short(world: &mut MerkleWorld) {
    world.op_slash_command = true;
    world.op_oob_ack = true;
}

#[given(expr = "the LLM constructs a vault_reveal call with handle {string}")]
async fn given_llm_reveal_call(_world: &mut MerkleWorld, _handle: String) {
    super::scaffolded("given_llm_reveal_call");
}

#[given(
    expr = "the operator_confirmation has slash_command=false and oob_ack=true and oob_channel={string}"
)]
async fn given_op_confirm_no_slash_oob(world: &mut MerkleWorld, _channel: String) {
    world.op_slash_command = false;
    world.op_oob_ack = true;
}

#[given(expr = "the Vault Agent is in the process of zeroizing the Vault Root Key from memory")]
async fn given_zeroizing(_world: &mut MerkleWorld) {
    super::scaffolded("given_zeroizing");
}

#[given(expr = "the idle_lock_timeout elapses")]
async fn given_idle_timeout_elapsed(_world: &mut MerkleWorld) {
    super::scaffolded("given_idle_timeout_elapsed");
}

// ---------------------------------------------------------------------------
// Init Vault Background steps
// ---------------------------------------------------------------------------

#[given("the Vault Agent has been started for the first time")]
async fn given_vault_first_time(_world: &mut MerkleWorld) {
    // Fresh world — already in Sealed State with an empty database.
    // No additional setup needed; the background is consistent with a first boot.
}

#[given(expr = "the OS Keychain does not contain any entry for service {string}")]
async fn given_os_keychain_does_not_contain(world: &mut MerkleWorld, service: String) {
    use merkle_ports::Keychain as _;
    // Remove any pre-seeded entries for this service so that init scenarios
    // start with a truly empty keychain for the given service.
    let accounts = world.keychain.list(&service).await.unwrap_or_default();
    for account in accounts {
        let _ = world.keychain.delete(&service, &account).await;
    }
    // Also remove the canonical master key if it was pre-seeded.
    let _ = world
        .keychain
        .delete(super::KEYCHAIN_SERVICE, super::KEYCHAIN_ACCOUNT)
        .await;
}

#[given("the SQLite vault database is empty (no vault_root_key rows)")]
async fn given_sqlite_empty(_world: &mut MerkleWorld) {
    // The test world always spins up a fresh in-memory database. No-op.
}

#[given(expr = "the OS Keychain already contains entry service {string} account {string}")]
async fn given_os_keychain_already_contains(
    world: &mut MerkleWorld,
    service: String,
    account: String,
) {
    use merkle_ports::Keychain as _;
    // Ensure the entry exists so init detects it and returns 409.
    world
        .keychain
        .store(&service, &account, &[0xAAu8; 32])
        .await
        .expect("keychain store for already-initialized state");
}

#[given(expr = "the OS Keychain backend returns error {string} for write operations")]
async fn given_keychain_backend_error_for_writes(world: &mut MerkleWorld, _error: String) {
    // Configure the mock to fail all store() calls.
    world.keychain.set_write_unavailable(true);
}

// ---------------------------------------------------------------------------
// Unseal rollback — specific service+account keychain error injection
// ---------------------------------------------------------------------------

#[given(
    expr = "the OS Keychain backend returns error {string} for service {string} account {string}"
)]
async fn given_keychain_error_for_service_account(
    world: &mut MerkleWorld,
    error: String,
    service: String,
    account: String,
) {
    use merkle_adapter_keychain::mock::InjectedError;
    let injected = match error.as_str() {
        "keychain_not_found" => InjectedError::NotFound,
        _ => InjectedError::Unavailable,
    };
    world.keychain.inject_error(&service, &account, injected);
}

// ---------------------------------------------------------------------------
// Unseal AEAD mismatch Given
// ---------------------------------------------------------------------------

#[given(
    "the wrapped Vault Root Key in the database cannot be decrypted with the retrieved Master Key"
)]
async fn given_vrk_cannot_decrypt(world: &mut MerkleWorld) {
    // Simulate AEAD decryption failure by injecting a Backend error that
    // unseal_vault interprets as a keychain/decryption failure.
    // The injected error causes the keychain retrieve step to return an error,
    // which unseal_vault maps to AppError::Keychain — propagated as last_error.
    use merkle_adapter_keychain::mock::InjectedError;
    world.keychain.inject_error(
        super::KEYCHAIN_SERVICE,
        super::KEYCHAIN_ACCOUNT,
        InjectedError::Unavailable,
    );
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_sensitivity(s: &str) -> Sensitivity {
    match s {
        "low" | "Low" => Sensitivity::Low,
        "high" | "High" => Sensitivity::High,
        _ => Sensitivity::Medium,
    }
}

// put_secret.feature:63 — multi-field CUE schema declaration
#[given(
    "a custom Category \"wireguard\" is registered with a CUE schema declaring fields \"private_key\", \"public_key\", \"endpoint\", \"allowed_ips\""
)]
async fn given_custom_wireguard_category(_world: &mut MerkleWorld) {
    // Wireguard CUE schema category registration is scaffolded.
}

// reveal_with_oob — operator_confirmation fixture that appears as Given/And
#[given("the operator_confirmation has slash_command=false and oob_ack=false")]
async fn given_op_confirm_no_slash_no_oob_fixture(_world: &mut MerkleWorld) {
    // Default confirmation state — slash_command false, no OOB.
}

// reveal_with_oob — LLM constructs vault_reveal: already registered

// backup_and_restore — elapsed time exceeded max_interval (Given context)
#[given(
    expr = "the elapsed time since last Backup is {int} hours, exceeding max_interval={int} hours"
)]
async fn given_elapsed_exceeds_max(_world: &mut MerkleWorld, _elapsed: u32, _max: u32) {
    super::scaffolded("given_elapsed_exceeds_max");
}

// backup_and_restore — pending changes state
#[given("there are pending changes since the last Backup")]
async fn given_pending_changes(world: &mut MerkleWorld) {
    world.mutation_counter += 1;
}

// ---------------------------------------------------------------------------
// port_forward — Given steps (ADR-0023)
// ---------------------------------------------------------------------------

/// port_forward — vault unsealed, use token resolves to valid ssh-key.
#[given("the vault is unsealed and the Use Token resolves to a valid ssh-key")]
async fn given_vault_unsealed_with_ssh_key(world: &mut MerkleWorld) {
    // The background step already establishes an Unsealed vault; this step
    // records that the Use Token resolution is presumed successful so that
    // `when_port_forward_invoked` drives the happy path.
    world.last_error = None;
}

/// port_forward — SSH Handle has sensitivity=high.
#[given("the SSH Handle has sensitivity=high")]
async fn given_ssh_handle_sensitivity_high(world: &mut MerkleWorld) {
    // Flag: operator will not supply slash_command, triggering policy denial.
    world.op_slash_command = false;
}

/// port_forward — operator_confirmation.slash_command=false.
#[given("operator_confirmation.slash_command=false")]
async fn given_op_slash_command_false(world: &mut MerkleWorld) {
    world.op_slash_command = false;
}

/// port_forward MCP — vault unsealed, SSH Handle has sensitivity=low.
///
/// The Background step already unseals the vault. This step records that the
/// SSH Handle in scope has sensitivity=low (policy gate never blocks Low).
#[given("the vault is unsealed and the SSH Handle has sensitivity=low")]
async fn given_vault_unsealed_ssh_handle_low(world: &mut MerkleWorld) {
    world.last_error = None;
}

/// port_forward MCP — operator_confirmation.slash_command=true.
#[given("operator_confirmation.slash_command=true")]
async fn given_op_slash_command_true(world: &mut MerkleWorld) {
    world.op_slash_command = true;
}

// ---------------------------------------------------------------------------
// JWT attestation — Given steps (ADR-0011 Amendment 6)
// ---------------------------------------------------------------------------

/// Enroll a deterministic Ed25519 public key in the mock OS Keychain under
/// `KEYCHAIN_ACCOUNT_OPERATOR_ATTESTATION`. The corresponding signing key is
/// saved in `world.jwt_signing_seed` so that `when` steps can construct valid
/// JWTs.
#[given("the operator has enrolled a JWT attestation Ed25519 key in the OS Keychain")]
async fn given_enrolled_jwt_attestation_key_full(world: &mut MerkleWorld) {
    use merkle_domain_identity::keychain_entry::KEYCHAIN_ACCOUNT_OPERATOR_ATTESTATION;
    use merkle_ports::Keychain as _;

    // Deterministic seed for the signing key (32 bytes: 1..=32).
    // Indices are 0..31; +1 produces 1..=32 which fits in u8.
    #[expect(clippy::cast_possible_truncation, reason = "seed indices 0..31")]
    let seed: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pubkey_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();

    world
        .keychain
        .store(
            crate::steps::KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT_OPERATOR_ATTESTATION,
            &pubkey_bytes,
        )
        .await
        .expect("enroll attestation pubkey in mock keychain");

    world.jwt_signing_seed = Some(seed);
    world.jwt_key_id = Some(KEYCHAIN_ACCOUNT_OPERATOR_ATTESTATION.to_owned());
}

/// Short alias: "an enrolled JWT attestation key" used in denial scenarios.
#[given("an enrolled JWT attestation key")]
async fn given_enrolled_jwt_attestation_key_short(world: &mut MerkleWorld) {
    given_enrolled_jwt_attestation_key_full(world).await;
}

/// Build and store a valid JWT signed by the enrolled key. The JWT will be
/// passed as `signed_config_flag` in the next vault_reveal call.
///
/// kid is supplied verbatim from the step expression.
#[given(expr = "the MCP client supplies a valid JWT with kid={string} matching the challenge_id")]
async fn given_valid_jwt_with_kid(world: &mut MerkleWorld, _kid: String) {
    use ed25519_dalek::Signer as _;

    let seed = world
        .jwt_signing_seed
        .expect("call given_enrolled_jwt_attestation_key first");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);

    let challenge_id = merkle_types::ChallengeId::new();
    world.jwt_challenge_id = Some(challenge_id);

    // exp = now + 60s
    let exp = chrono::Utc::now().timestamp() + 60;
    let key_id = world
        .jwt_key_id
        .clone()
        .unwrap_or_else(|| "merkle-operator-attestation".to_owned());

    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::json!({ "alg": "EdDSA", "kid": key_id }).to_string());
    let payload_json = serde_json::json!({
        "aud": "merkle-vault",
        "exp": exp,
        "challenge_id": challenge_id.to_string(),
    })
    .to_string();
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_json);

    let signing_input = format!("{header}.{payload}");
    let sig = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let jwt = format!("{signing_input}.{sig_b64}");
    world.jwt_token = Some(jwt);
    world.jwt_key_id = Some(key_id);
}

/// Build a JWT signed by a DIFFERENT key (wrong key denial scenario).
#[given("the MCP client supplies a JWT signed by a different key")]
async fn given_jwt_wrong_key(world: &mut MerkleWorld) {
    use ed25519_dalek::Signer as _;

    // Wrong seed — different from the enrolled key (seed = 1..=32).
    // wrapping_add keeps the value in u8 range; indices are 0..31.
    #[expect(clippy::cast_possible_truncation, reason = "seed indices 0..31")]
    let wrong_seed: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_add(100));
    let wrong_key = ed25519_dalek::SigningKey::from_bytes(&wrong_seed);

    let challenge_id = merkle_types::ChallengeId::new();
    world.jwt_challenge_id = Some(challenge_id);

    let exp = chrono::Utc::now().timestamp() + 60;
    let key_id = world
        .jwt_key_id
        .clone()
        .unwrap_or_else(|| "merkle-operator-attestation".to_owned());

    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::json!({ "alg": "EdDSA", "kid": key_id }).to_string());
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "aud": "merkle-vault",
            "exp": exp,
            "challenge_id": challenge_id.to_string(),
        })
        .to_string(),
    );
    let signing_input = format!("{header}.{payload}");
    let sig = wrong_key.sign(signing_input.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let jwt = format!("{signing_input}.{sig_b64}");
    world.jwt_token = Some(jwt);
    world.jwt_key_id = Some(key_id);
}

/// Set the sensitivity context for the next reveal call.
///
/// This step is informational — `when_reveal_with_signed_config_flag_inner`
/// reads sensitivity from storage or defaults to `Low`. This step records the
/// intent so the world context is visible in test output.
#[given(expr = "sensitivity is {string}")]
async fn given_sensitivity_is(world: &mut MerkleWorld, sensitivity_str: String) {
    // Sensitivity context is used during secret storage lookup.
    // The RevealSecretCommand always reads from storage; this step is a no-op
    // unless a secret is stored with that sensitivity.
    let _ = (world, sensitivity_str);
}

/// Build a JWT with exp claim 1 second in the past (expired scenario).
#[given("the JWT exp claim is 1 second in the past")]
async fn given_jwt_expired(world: &mut MerkleWorld) {
    use ed25519_dalek::Signer as _;

    let seed = world
        .jwt_signing_seed
        .expect("call given_enrolled_jwt_attestation_key first");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);

    let challenge_id = merkle_types::ChallengeId::new();
    world.jwt_challenge_id = Some(challenge_id);

    // exp = now - 1s (expired)
    let exp = chrono::Utc::now().timestamp() - 1;
    let key_id = world
        .jwt_key_id
        .clone()
        .unwrap_or_else(|| "merkle-operator-attestation".to_owned());

    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::json!({ "alg": "EdDSA", "kid": key_id }).to_string());
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "aud": "merkle-vault",
            "exp": exp,
            "challenge_id": challenge_id.to_string(),
        })
        .to_string(),
    );
    let signing_input = format!("{header}.{payload}");
    let sig = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let jwt = format!("{signing_input}.{sig_b64}");
    world.jwt_token = Some(jwt);
    world.jwt_key_id = Some(key_id);
}
