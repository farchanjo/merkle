Feature: Unsealing the Vault Agent

  The Vault Agent starts in Sealed State after every boot. The Unseal Protocol
  transitions the agent to Unsealed State by fetching the Master Key from the
  OS Keychain or, when no keychain is available, deriving it from a user
  passphrase via Argon2id. Until unseal succeeds, all read and write operations
  are rejected. Idle re-lock returns the agent to Sealed State after the
  configured timeout elapses.

  Background:
    Given the Vault Agent is freshly booted and in Sealed State
    And the vault database is located at "/Users/farchanjo/.local/share/merkle/vault.db"
    And the Vault Root Key is wrapped in the database under namespace "0192ac11-7000-7000-8000-000000000001"

  Scenario: Successful unseal using OS Keychain
    Given the OS Keychain entry "dev.fapp.merkle" account "master-v1" is present and readable
    When the Vault Agent executes the Unseal Protocol
    Then the Master Key is retrieved from the OS Keychain without prompting the operator
    And the Vault Root Key is decrypted using the Master Key and held in protected memory
    And the Vault Agent transitions to Unsealed State
    And an Audit Entry with op "unseal" and outcome "allow" is appended to the Audit Log

  Scenario: Successful unseal using Argon2id passphrase fallback when keychain unavailable
    Given the OS Keychain backend returns error "keychain_unavailable"
    And the operator provides the passphrase "correct-horse-battery-staple"
    When the Vault Agent executes the Unseal Protocol
    Then the Master Key is derived from the passphrase using Argon2id (RFC 9106) parameters stored in config.toml
    And the Vault Root Key is decrypted using the derived Master Key and held in protected memory
    And the Vault Agent transitions to Unsealed State
    And an Audit Entry with op "unseal", outcome "allow", and note "argon2id_fallback" is appended to the Audit Log

  Scenario: Failed unseal due to wrong passphrase
    Given the OS Keychain backend returns error "keychain_unavailable"
    And the operator provides the passphrase "wrong-passphrase-attempt"
    When the Vault Agent executes the Unseal Protocol
    Then the derived key fails AEAD authentication when decrypting the Vault Root Key
    And the Vault Agent remains in Sealed State
    And an Audit Entry with op "unseal", outcome "error", and denial_reason "passphrase_invalid" is appended to the Audit Log
    And the agent reports error "unseal_authentication_failed" without revealing key material
    And the operator may retry the Unseal Protocol with a corrected passphrase

  Scenario: Unseal attempt when already in Unsealed State is a no-op
    Given the Vault Agent is already in Unsealed State
    When the Vault Agent receives a second unseal request
    Then the Vault Agent remains in Unsealed State without re-executing the Unseal Protocol
    And no Audit Entry is appended for the redundant request
    And the agent returns status "already_unsealed"

  Scenario: Unseal attempt is denied while the agent is shutting down
    Given the Vault Agent has received a shutdown signal
    And the Vault Agent is in the process of zeroizing the Vault Root Key from memory
    When an unseal request arrives during the shutdown window
    Then the agent rejects the request with error "agent_shutting_down"
    And the Vault Agent remains in Sealed State after zeroization completes
    And no Audit Entry is appended for the rejected request

  Scenario: Idle re-lock after configured timeout
    Given the Vault Agent is in Unsealed State
    And the Namespace Policy specifies idle_lock_timeout of 30 minutes
    And no Secret operation has been performed for 30 minutes
    When the idle_lock_timeout elapses
    Then the Vault Agent zeroizes the Vault Root Key from protected memory
    And the Vault Agent transitions back to Sealed State
    And an Audit Entry with op "idle_relock" and outcome "allow" is appended to the Audit Log
    And all subsequent read and write operations are rejected until a new unseal succeeds

  Scenario: Unseal denied when vault_state is corrupted or null
    Given the vault database exists but the vault_state field is null or contains an unrecognized value
    When the Vault Agent executes the Unseal Protocol
    Then the Vault Agent cannot resolve a valid Sealed or Unsealed state from vault_state
    And the Vault Agent rejects the unseal with error "vault_state_corrupted"
    And the Vault Agent remains in Sealed State
    And an Audit Entry with op "unseal", outcome "deny", and denial_reason "vault_state_corrupted" is appended to the Audit Log

  Scenario: Unseal fails when keychain entry is missing and state rolls back cleanly
    Given the OS Keychain backend returns error "keychain_not_found" for service "dev.fapp.merkle" account "master-v1"
    When the Vault Agent executes the Unseal Protocol
    Then the Vault Agent transitions to Unsealing State to begin the protocol
    And the keychain fetch fails with denial_reason "keychain_not_found"
    And the Vault Agent reverts the state back to Sealed State before propagating the error
    And an Audit Entry with op "unseal", outcome "error", and denial_reason "keychain_not_found" is appended to the Audit Log
    And the agent reports error "unseal_authentication_failed"
    And the operator may retry the Unseal Protocol immediately without restarting the agent

  Scenario: Unseal fails on AEAD verification mismatch and state rolls back cleanly
    Given the OS Keychain entry "dev.fapp.merkle" account "master-v1" is present and readable
    And the wrapped Vault Root Key in the database cannot be decrypted with the retrieved Master Key
    When the Vault Agent executes the Unseal Protocol
    Then the Vault Agent transitions to Unsealing State to begin the protocol
    And the AEAD decryption fails with denial_reason "aead_verify_failed"
    And the Vault Agent reverts the state back to Sealed State before propagating the error
    And an Audit Entry with op "unseal", outcome "error", and denial_reason "aead_verify_failed" is appended to the Audit Log
    And the agent reports error "unseal_authentication_failed"
    And the Vault Agent remains in Sealed State

  Scenario: Two successive failed unseal attempts both transition cleanly without invalid state errors
    Given the OS Keychain backend returns error "keychain_not_found" for service "dev.fapp.merkle" account "master-v1"
    When the Vault Agent executes the Unseal Protocol for the first time
    Then the first attempt fails with error "unseal_authentication_failed"
    And the Vault Agent is in Sealed State after the first attempt
    When the Vault Agent executes the Unseal Protocol for the second time
    Then the second attempt fails with error "unseal_authentication_failed" and not with "invalid state transition"
    And the Vault Agent is in Sealed State after the second attempt
    And two Audit Entries with op "unseal" and outcome "error" are present in the Audit Log

  Scenario: Unseal denied when Argon2id parameters are below minimum required values
    Given the OS Keychain backend returns error "keychain_unavailable"
    And config.toml declares Argon2id parameters with m_cost=32768 and t_cost=2
    And the operator provides the passphrase "correct-horse-battery-staple"
    When the Vault Agent executes the Unseal Protocol
    Then the Vault Agent validates the configured Argon2id parameters against the minimum requirements
    And m_cost=32768 is below the minimum of 65536 required by ADR-0005
    And t_cost=2 is below the minimum of 3 required by ADR-0005
    And the Vault Agent rejects the unseal with error "argon2id_parameters_below_minimum"
    And the Vault Agent remains in Sealed State
    And an Audit Entry with op "unseal", outcome "deny", and denial_reason "argon2id_parameters_below_minimum" is appended to the Audit Log
