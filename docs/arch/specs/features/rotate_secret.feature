Feature: Rotating a Secret's material

  The vault.rotate MCP Tool replaces the active Private Blob of a Secret with new
  material, increments the Secret Version, and retains previous versions up to the
  retain_count limit declared in the Namespace Policy (default retain_count=3).
  Versions beyond the retain_count are pruned. A Rollback to a previous Secret Version
  requires Operator Confirmation via Slash Command. Rotation triggers a pre-snapshot
  Backup to preserve state before modification. Secrets approaching their expires_at
  threshold emit a warning seven days before expiry. Rotation is rejected when the
  Vault Agent is in Sealed State.

  Background:
    Given the Vault Agent is in Unsealed State
    And a Secret with Handle "vault://acme-backend/ssh/bastion-prod" exists in namespace "acme-backend"
    And that Secret has current Version 3 with created_at "2026-04-01T00:00:00Z"
    And the Namespace Policy for "acme-backend" declares retain_count=3
    And Secret Version history is
      | version | created_at              |
      | 3       | 2026-04-01T00:00:00Z    |
      | 2       | 2026-03-01T00:00:00Z    |
      | 1       | 2026-02-01T00:00:00Z    |

  Scenario: Rotate an ssh Secret and retain previous versions up to retain_count=3
    When the operator calls vault.rotate with handle "vault://acme-backend/ssh/bastion-prod" and new key material
    Then the Vault Agent creates Secret Version 4 with the new Private Blob encrypted with the Namespace DEK
    And Versions 1, 2, and 3 are retained in the database as historical Secret Versions
    And the active version is set to Version 4
    And an Audit Entry with op "rotate", handle "vault://acme-backend/ssh/bastion-prod", and outcome "allow" is appended
    And the MCP response contains the Handle and the new version number 4

  Scenario: Old versions beyond retain_count are pruned after rotation
    Given the Secret "vault://acme-backend/ssh/bastion-prod" has 3 retained versions (1, 2, 3) plus the new version 4
    When a second rotation creates Version 5
    Then Version 1 is the oldest version exceeding retain_count=3
    And Version 1 is deleted from the database
    And Versions 2, 3, and 4 are retained as historical Secret Versions
    And Version 5 is the active version
    And an Audit Entry with op "rotate" and note "pruned_version=1" is appended

  Scenario: Rollback to previous version requires Slash Command confirmation
    Given the Secret "vault://acme-backend/ssh/bastion-prod" has active Version 4 and retained Versions 2 and 3
    When the operator issues the Slash Command "/merkle-rollback vault://acme-backend/ssh/bastion-prod version=3"
    And the Slash Command carries a verified Operator Confirmation flag
    Then the Vault Agent sets active version to Version 3
    And the previously active Version 4 is retained as a non-active Secret Version
    And an Audit Entry with op "rollback", handle "vault://acme-backend/ssh/bastion-prod", target_version=3, and outcome "allow" is appended
    But if the rollback request arrives without a verified Operator Confirmation flag
    Then the Vault Agent rejects it with error "operator_confirmation_required"

  Scenario: Rotate triggers a pre-snapshot Backup before applying changes
    When the operator calls vault.rotate with handle "vault://acme-backend/ssh/bastion-prod" and new key material
    Then before writing the new Secret Version, the Vault Agent initiates a Backup of the current vault state
    And the Backup is encrypted with two age recipients: Master public key and Recovery Public Key
    And the Backup file is written to the configured target directory as "merkle-bk-<utc-iso8601>.merkle.age"
    And only after the Backup completes successfully does the rotation proceed
    And an Audit Entry with op "backup" and note "pre_rotate_snapshot" is appended before the rotate entry

  Scenario: Secrets approaching expires_at emit warning seven days before expiry
    Given a Secret with Handle "vault://acme-backend/cert/api-tls" has expires_at "2026-05-29T00:00:00Z"
    And the current date is "2026-05-22T00:00:00Z"
    When the operator calls vault.list or vault.describe for namespace "acme-backend"
    Then the MCP response includes a warning for "vault://acme-backend/cert/api-tls" with message "expires_in_7_days"
    And the warning is also recorded as an Audit Entry with op "expiry_warning" and handle "vault://acme-backend/cert/api-tls"
    And the Secret is still accessible and not automatically revoked

  Scenario: Rotation fails when the Vault Agent is in Sealed State
    Given the Vault Agent is in Sealed State
    When the LLM calls vault.rotate with handle "vault://acme-backend/ssh/bastion-prod" and new key material
    Then the Vault Agent rejects the request with error "agent_sealed"
    And no rotation is performed
    And no Backup is triggered
    And no Audit Entry is appended because the agent cannot access the Audit Log in Sealed State

  Scenario: RotateSecret preserves AD binding across versions
    Given the Vault Agent is in Unsealed State
    And a Secret at handle "vault://acme/password/api-key" exists with Version 1 encrypted using Associated Data "vault://acme/password/api-key"
    When the operator calls vault.rotate with handle "vault://acme/password/api-key" and new key material
    Then the new SecretVersion has its Private Blob encrypted via XChaCha20-Poly1305 with Associated Data equal to the Handle URI bytes "vault://acme/password/api-key"
    And the new version's associated_data matches the handle column of the same row
    And the previous Version 1 remains decryptable using Associated Data "vault://acme/password/api-key"
    And an Audit Entry with op "rotate", outcome "allow", and handle "vault://acme/password/api-key" is appended
