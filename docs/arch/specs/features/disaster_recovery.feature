Feature: Disaster Recovery via Recovery Key

  When the Master Key is unavailable because the OS Keychain has been wiped, the
  operating system has been reinstalled, or hardware has been lost, the operator
  performs Disaster Recovery. The operator supplies the Recovery Key (the age X25519
  secret key shown once at merkle init) to decrypt the Backup. The Vault Agent
  generates a fresh Master Key, re-wraps the Vault Root Key, stores the new Master Key
  in the OS Keychain, and appends a special marker entry to the Audit Log. The Recovery
  Key fingerprint is verified against the recovery_pubkey stored in config.toml before
  any unwrap is attempted.

  Background:
    Given a fresh machine with no OS Keychain entry for "dev.fapp.merkle"
    And a Backup file "merkle-bk-2026-05-21T08:00:00Z.merkle.age" is available on removable media
    And the Backup was encrypted with two age recipients: the original Master public key and the Recovery Public Key
    And the Recovery Public Key fingerprint stored in config.toml is "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq"

  Scenario: Restore from backup using the Recovery Key provided by the operator
    Given the operator has the Recovery Key (age X25519 secret key) "AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP"
    When the operator calls merkle recover with the Backup file and the Recovery Key
    Then the Vault Agent derives the Recovery Public Key fingerprint from the supplied Recovery Key
    And the fingerprint matches "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq" stored in config.toml
    And the Vault Agent decrypts the Backup using the Recovery Key as the age recipient
    And all Secrets and Audit Log entries from the Backup are loaded into the restored vault database
    And the Vault Agent transitions to Unsealed State after re-wrapping succeeds

  Scenario: Vault Agent generates a new Master Key and re-wraps the Vault Root Key after recovery
    Given the Backup has been successfully decrypted using the Recovery Key
    When the Vault Agent executes the re-wrap procedure
    Then a fresh 32-byte Master Key is generated using a cryptographically secure random source
    And the Vault Root Key from the Backup is re-wrapped using the new Master Key
    And the re-wrapped Vault Root Key is stored in the restored vault database
    And the new Master Key is stored in the OS Keychain under service "dev.fapp.merkle" account "master-v1"
    And the Vault Root Key is additionally re-wrapped for the same Recovery Public Key for future recovery
    And subsequent Unseal Protocol calls use the new Master Key from the OS Keychain

  Scenario: Restored Audit Log preserves the original hash chain and adds a recovery marker entry
    Given the Backup contains an Audit Log with 500 entries forming an intact Hash Chain
    When the Vault Agent restores the Backup and completes re-wrapping
    Then all 500 original Audit Entries are loaded into the Audit Log in their original order
    And the Hash Chain of the original 500 entries remains intact as verified by the Chain Verifier
    And a new Audit Entry with op "disaster_recovery", outcome "allow", and note "chain_continued_after_recovery" is appended as entry 501
    And the entry 501 hash is chained from entry 500 maintaining Hash Chain continuity

  Scenario: Recovery Key fingerprint is verified before the Backup is unwrapped
    Given the operator supplies a Recovery Key that is valid but belongs to a different vault
    And the derived fingerprint of the supplied key is "age1differentfingerprintxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    When the operator calls merkle recover with the Backup file and that Recovery Key
    Then the Vault Agent computes the fingerprint of the supplied Recovery Key
    And the computed fingerprint does not match "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq" in config.toml
    And the Vault Agent rejects the recovery with error "recovery_key_fingerprint_mismatch"
    And no decryption of the Backup is attempted
    And the vault database remains untouched
    And an Audit Entry with op "disaster_recovery", outcome "deny", and denial_reason "recovery_key_fingerprint_mismatch" is appended to a bootstrap log

  Scenario: Restore is denied when the Recovery Key fingerprint does not match the recorded recovery_pubkey
    Given the config.toml on the fresh machine has been tampered and records a wrong recovery_pubkey fingerprint
    When the operator supplies the genuine Recovery Key
    Then the Vault Agent computes the fingerprint from the supplied key
    And the computed fingerprint does not match the tampered entry in config.toml
    And the Vault Agent rejects the recovery with error "recovery_key_fingerprint_mismatch"
    And an informational message advises the operator to verify config.toml integrity or supply the original config.toml from backup
