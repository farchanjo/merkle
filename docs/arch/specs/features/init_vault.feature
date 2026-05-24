Feature: Initializing a fresh Vault

  The Init Vault Bootstrap Ceremony generates the Master Key, the Recovery Key,
  and the Vault Root Key for a fresh installation. It persists the Master Key in
  the OS Keychain, dual-wraps the Vault Root Key in SQLite, displays the Recovery
  Key exactly once on stdout, and appends an Audit Entry with op=init. The ceremony
  is idempotent: a second call on an already-initialized vault returns 409 without
  touching any existing key material.

  Background:
    Given the Vault Agent has been started for the first time
    And the OS Keychain does not contain any entry for service "dev.fapp.merkle"
    And the SQLite vault database is empty (no vault_root_key rows)

  Scenario: Successful init on a fresh vault returns 201 with Recovery Key
    When the operator calls POST /v1/agent/init with body
      | field            | value    |
      | interactive      | false    |
      | security_profile | balanced |
    Then the Vault Agent generates a 32-byte Master Key using OsRng
    And the Vault Agent stores the Master Key in the OS Keychain under service "dev.fapp.merkle" account "master-v1"
    And the Vault Agent generates an age X25519 Recovery Key identity
    And the Vault Agent generates a 32-byte Vault Root Key using OsRng
    And the Vault Agent writes exactly two rows to vault_root_key with version=1
    And one row has wrapped_by="master" and one row has wrapped_by="recovery"
    And both rows are written in a single atomic SQLite transaction
    And an Audit Entry with op "init" and outcome "allow" is appended to the Audit Log
    And the agent responds with HTTP 201 containing fields vault_id, recovery_key, and master_key_keychain_ref
    And the recovery_key field is a valid age X25519 public key string
    And the master_key_keychain_ref value is "dev.fapp.merkle/master-v1"

  Scenario: Init is refused when the vault is already initialized returns 409
    Given the OS Keychain already contains entry service "dev.fapp.merkle" account "master-v1"
    When the operator calls POST /v1/agent/init with body
      | field            | value    |
      | interactive      | false    |
      | security_profile | balanced |
    Then the Vault Agent detects the existing keychain entry without reading its value
    And the agent responds with HTTP 409 and problem type "already_initialized"
    And no new keys are generated
    And no new database rows are written
    And no Audit Entry is appended for the refused call
    And the existing Master Key and Vault Root Key are not modified

  Scenario: Non-interactive init still displays Recovery Key on stdout
    When the operator calls POST /v1/agent/init with body
      | field            | value    |
      | interactive      | false    |
      | security_profile | balanced |
    Then the agent responds with HTTP 201
    And the recovery_key field in the response body contains the age public key string
    And the CLI prints the recovery_key to stdout before any other output
    And the CLI does not print an interactive confirmation prompt
    And the vault is fully initialized with Vault Root Key persisted in the database

  Scenario: Init creates the keychain entry under the canonical service identifier
    When the operator calls POST /v1/agent/init with body
      | field            | value    |
      | interactive      | true     |
      | security_profile | balanced |
    Then the agent responds with HTTP 201
    And the OS Keychain entry is stored with service exactly "dev.fapp.merkle"
    And the OS Keychain account field is exactly "master-v1"
    And a subsequent POST /v1/agent/unseal succeeds with method "keychain"
    And the Vault Agent transitions to Unsealed State

  Scenario: Init fails cleanly when OS Keychain write fails
    Given the OS Keychain backend returns error "keychain_unavailable" for write operations
    When the operator calls POST /v1/agent/init with body
      | field            | value    |
      | interactive      | false    |
      | security_profile | balanced |
    Then the Vault Agent attempts to store the Master Key in the OS Keychain
    And the keychain write fails with "keychain_unavailable"
    And the Vault Agent aborts the ceremony before writing any database rows
    And the agent responds with HTTP 503 and problem type "keychain_unavailable"
    And no database rows are written
    And no Audit Entry is appended

  Scenario: Init aborts when Keychain write does not persist (headless context)
    Given the OS Keychain backend silently fails to persist writes (background process without GUI auth)
    And the operator runs "merkle init --non-interactive"
    When the Vault Agent attempts to store the Master Key in the OS Keychain under service "dev.fapp.merkle" account "master-v1"
    And the post-write verify retrieve returns NotFound
    Then the Vault Agent aborts the init ceremony with error "keychain_persistence_failed"
    And no Recovery Key is displayed
    And no Vault Root Key is generated
    And the operator receives guidance to run with file-backed keystore fallback
