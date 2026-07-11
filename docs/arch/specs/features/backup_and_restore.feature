Feature: Backup and Restore lifecycle

  The Vault Agent maintains an encrypted Backup of the vault state. Backups are
  age-encrypted with two recipients: the Master public key and the Recovery Public Key.
  Triggers include manual requests, the Anacron Trigger at boot, Change-Triggered Backup
  after a configurable number of mutations, Idle-Triggered Backup after a configurable
  idle period, and a Sleep Hook on imminent system sleep. Restore supports three modes:
  overwrite, merge, and newest-wins. A preview step shows changes before applying.
  HMAC verification detects tampered backup files.

  Background:
    Given the Vault Agent is in Unsealed State
    And the vault contains 12 Secrets across namespaces "acme-backend" and "acme-infra"
    And the configured backup target directory is "/Users/farchanjo/.local/share/merkle/backups"
    And the Namespace Policy declares max_interval=86400 (24 hours) and change_threshold=10

  Scenario: Manual backup writes an encrypted file to the configured target directory
    When the operator calls vault_backup with mode "manual"
    Then the Vault Agent serializes the full vault state including all Secrets and Audit Log entries
    And the serialized payload is encrypted using age with recipients: Master public key and Recovery Public Key
    And the Backup file is written to "/Users/farchanjo/.local/share/merkle/backups/merkle-bk-<utc-iso8601>.merkle.age"
    And the Backup file is readable only by the vault process (mode 0600)
    And an Audit Entry with op "backup", trigger "manual", and outcome "allow" is appended
    And the last_backup_ts in config.toml is updated to the current UTC timestamp

  Scenario: Anacron trigger fires a Backup at boot when last backup exceeds max_interval
    Given the last_backup_ts recorded in config.toml is "2026-05-21T08:00:00Z"
    And the current boot time is "2026-05-22T10:00:00Z"
    And the elapsed time since last Backup is 26 hours, exceeding max_interval=24 hours
    And there are pending changes since the last Backup
    When the Vault Agent boots and executes the Anacron Trigger check
    Then the Anacron Trigger determines the interval has elapsed
    And the Vault Agent initiates a Backup automatically without operator action
    And the Backup file is written to the configured target directory
    And an Audit Entry with op "backup", trigger "anacron", and outcome "allow" is appended

  Scenario: Change-triggered Backup fires after the configured number of mutations
    Given the change counter has accumulated 9 mutations since the last Backup
    When the operator calls vault_put to create a new Secret, making the 10th mutation
    Then the change counter reaches the change_threshold of 10
    And the Vault Agent initiates a Change-Triggered Backup without operator action
    And the Backup file is written to the configured target directory
    And the change counter is reset to 0
    And an Audit Entry with op "backup", trigger "change_triggered", and outcome "allow" is appended

  Scenario: Restore merge mode preserves newer local Secrets
    Given a Backup file "merkle-bk-2026-05-20T12:00:00Z.merkle.age" exists in the target directory
    And the Backup contains Secret "vault://acme-backend/ssh/bastion-prod" at Version 2 with updated_at "2026-05-19T00:00:00Z"
    And the local vault contains the same Secret at Version 3 with updated_at "2026-05-21T00:00:00Z"
    When the operator calls vault_restore with file "merkle-bk-2026-05-20T12:00:00Z.merkle.age" and mode "merge"
    Then the Vault Agent validates the Backup HMAC before applying any changes
    And the Vault Agent determines the local Version 3 is newer than the Backup Version 2
    And the merge mode preserves the local Version 3 for "vault://acme-backend/ssh/bastion-prod"
    And only Secrets absent from the local vault or newer in the Backup are imported
    And an Audit Entry with op "restore", mode "merge", and outcome "allow" is appended

  Scenario: Restore preview shows a diff of changes before the operator applies them
    Given a Backup file "merkle-bk-2026-05-18T08:00:00Z.merkle.age" exists in the target directory
    When the operator calls vault_restore with that file and flag "preview=true"
    Then the Vault Agent decrypts the Backup and computes the diff against the current vault state
    And the MCP response contains a list of changes with fields: handle, action, local_version, backup_version
    And the action field is one of "add", "overwrite", "skip", or "conflict"
    But no changes are applied to the vault database
    And no Audit Entry for "restore" is appended because the preview is read-only
    When the operator confirms with "preview=false"
    Then the changes are applied and an Audit Entry with op "restore" and outcome "allow" is appended

  Scenario: HMAC verification fails on a tampered backup file
    Given a Backup file "merkle-bk-2026-05-20T12:00:00Z.merkle.age" exists but has been modified after creation
    When the operator calls vault_restore with that file
    Then the Vault Agent computes the HMAC Signature over the decrypted payload
    And the computed HMAC does not match the stored HMAC Signature in the file header
    And the Vault Agent rejects the restore with error "backup_integrity_check_failed"
    And no changes are applied to the vault database
    And an Audit Entry with op "restore", outcome "deny", and denial_reason "backup_integrity_check_failed" is appended
