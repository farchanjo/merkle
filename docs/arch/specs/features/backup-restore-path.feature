Feature: Backup Restore Path product enablement
  The Companion Socket restore-plan and restore apply endpoints must leave the
  hard 501 gate once durable RestorePlan storage, Backup HMAC verification,
  dual operator confirmation, and secret rehydration are complete.
  Lifecycle scenarios remain in backup_and_restore.feature; this feature gates
  the product path (Feature 002 / ADR-0034).

  Background:
    Given the Vault Agent is in Unsealed State
    And a valid age-encrypted Backup exists in the configured backup directory
    And restore_available is true after durable plan storage is configured

  Scenario: Restore plan returns 200 instead of 501
    When the operator calls POST /v1/backup/restore-plan with mode "merge"
    Then the response status is 200
    And the body contains plan_id, mode, conflicts, and expires_at
    And no vault secret rows change

  Scenario: Restore apply rehydrates secrets after dual confirmation
    Given a non-expired restore plan exists for that Backup
    And operator_confirmation.slash_command is true
    And operator_confirmation.oob_ack is true
    When the operator calls POST /v1/backup/restore with that plan_id
    Then the response status is 200
    And secrets from the Backup are upserted according to the plan mode
    And an Audit Entry with op "restore" and outcome "allow" is appended
    And secrets_restored equals the number of applied rows

  Scenario: Tampered backup is rejected before mutation
    Given the Backup file bytes were modified after creation
    When the operator calls POST /v1/backup/restore-plan for that file
    Then the agent rejects with error "backup_integrity_check_failed"
    And no vault secret rows change
    And an Audit Entry with op "restore", outcome "deny", and denial_reason "backup_integrity_check_failed" is appended

  Scenario: Missing operator confirmation blocks apply
    Given a non-expired restore plan exists
    And operator_confirmation.oob_ack is false
    When the operator calls POST /v1/backup/restore with that plan_id
    Then the response status is 403
    And the problem type is OperatorConfirmationRequired
    And no vault secret rows change
