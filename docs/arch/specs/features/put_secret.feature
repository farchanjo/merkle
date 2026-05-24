Feature: Creating a new Secret

  The vault.put MCP Tool creates a new Secret under the bound Namespace, validates
  the input against the Category schema, enforces Namespace Policy rules such as
  tag requirements for sensitivity=high, detects duplicate fingerprints, and
  appends an Audit Entry. The Private Blob is encrypted with the Namespace DEK
  using XChaCha20-Poly1305 before persistence. The MCP transport receives only the
  Handle and Public Metadata in response.

  Background:
    Given the Vault Agent is in Unsealed State
    And a Namespace with label "acme-backend" and id "0192ac11-7000-7000-8000-000000000010" is bound for the session
    And the Namespace Policy allows secrets of all built-in categories
    And the Namespace DEK for "acme-backend" is loaded in agent memory

  Scenario: Create a new ssh Secret in the cwd-bound Namespace
    When the operator calls vault.put with the following parameters
      | field        | value                                      |
      | name         | bastion-prod                               |
      | category     | ssh                                        |
      | sensitivity  | medium                                     |
      | tags         | [{key: env, value: prod}, {key: role, value: bastion}] |
      | private_blob | { "private_key": "<rsa-pem>", "user": "deploy", "host": "bastion.prod.acme.io", "port": 22 } |
    Then the Private Blob is encrypted using XChaCha20-Poly1305 with the Namespace DEK and a fresh Nonce
    And a new Secret with Handle "vault://acme-backend/ssh/bastion-prod" is persisted to SQLite
    And the FTS5 Index is updated with the Secret's Public Metadata
    And an Audit Entry with op "put", outcome "allow", and handle "vault://acme-backend/ssh/bastion-prod" is appended
    And the MCP response contains the Handle and Public Metadata but not the Private Blob

  Scenario: Create with tags including env:prod when sensitivity is high
    When the operator calls vault.put with the following parameters
      | field       | value                           |
      | name        | deploy-token-prod               |
      | category    | token                           |
      | sensitivity | high                            |
      | tags        | [{key: env, value: prod}, {key: project, value: acme}, {key: role, value: ci}] |
    Then the Namespace Policy validates that at least one tag matches the pattern "env:*"
    And the Secret is persisted with sensitivity "high" and tags "env:prod, project:acme, role:ci"
    And the Handle returned is "vault://acme-backend/token/deploy-token-prod"

  Scenario: Reject put when sensitivity=high without env:* tag
    When the operator calls vault.put with the following parameters
      | field       | value             |
      | name        | admin-password    |
      | category    | password          |
      | sensitivity | high              |
      | tags        | [{key: project, value: acme}] |
    Then the Vault Agent rejects the request with error "policy_tag_required"
    And the error message states that tag matching "env:*" is mandatory for sensitivity=high
    And no Secret is persisted to SQLite
    And an Audit Entry with op "put" and outcome "rejected_policy" is appended

  Scenario: Detect duplicate fingerprint and emit warning before storing
    Given a Secret named "bastion-prod" with category "ssh" already exists in namespace "acme-backend"
    And the existing Secret has a content fingerprint "sha256:aabbccdd11223344"
    When the operator calls vault.put with a Private Blob whose fingerprint is "sha256:aabbccdd11223344"
    Then the Vault Agent detects the matching fingerprint before persisting
    And the MCP response includes warning "duplicate_fingerprint_detected" with the existing Handle
    And the operator must confirm with flag "force=true" to proceed with storage
    But the duplicate Secret is not persisted until the operator provides "force=true"

  Scenario: Create a Secret under a custom Category with declared CUE schema
    Given a custom Category "wireguard" is registered with a CUE schema declaring fields "private_key", "public_key", "endpoint", "allowed_ips"
    When the operator calls vault.put with category "wireguard" and a conformant Private Blob
    Then the Vault Agent validates the Private Blob against the "wireguard" CUE schema
    And the validation passes because all required fields are present and typed correctly
    And the Secret is persisted with category "wireguard" and the correct Handle format "vault://acme-backend/wireguard/<name>"

  Scenario: Reject put when category is not registered
    When the operator calls vault.put with the following parameters
      | field    | value          |
      | name     | my-secret      |
      | category | unregistered   |
    Then the Vault Agent rejects the request with error "category_not_registered"
    And the error response lists the available built-in categories: ssh, password, token, env, cert, key, database, note, otp, cloud, gpg
    And no Secret is persisted to SQLite

  Scenario: PutSecret rejects expose=true when sensitivity=high
    When the operator calls vault.put with the following parameters
      | field       | value                                              |
      | name        | db-admin-exposed                                   |
      | category    | password                                           |
      | sensitivity | high                                               |
      | expose      | true                                               |
      | tags        | [{key: env, value: prod}]                          |
    Then the Vault Agent rejects the request with error "expose_not_allowed_for_high_sensitivity"
    And the error message states that expose=true is forbidden when sensitivity=high per ADR-0011
    And no Secret is persisted to SQLite
    And an Audit Entry with op "put", outcome "deny", and denial_reason "expose_not_allowed_for_high_sensitivity" is appended

  Scenario: PutSecret binds Handle as AEAD Associated Data
    Given the Vault Agent is in Unsealed State
    And a Namespace with label "acme" is bound for the session
    And the Namespace DEK for "acme" is loaded in agent memory
    When the operator calls vault.put with the following parameters
      | field       | value                    |
      | name        | db-admin                 |
      | category    | password                 |
      | sensitivity | medium                   |
    Then the encrypted Private Blob is produced via XChaCha20-Poly1305 with Associated Data equal to the Handle URI bytes "vault://acme/password/db-admin"
    And the Handle URI is passed as the associated_data argument on every encryption call per ADR-0004 Amendment
    And an Audit Entry with op "put", outcome "allow", handle "vault://acme/password/db-admin", and denial_reason absent is appended

  Scenario: PutSecret denies ciphertext transplant attempt
    Given the Vault Agent is in Unsealed State
    And a Namespace with label "acme" is bound for the session
    And a Secret at handle "vault://acme/password/db-admin" was previously encrypted with Associated Data "vault://acme/password/db-admin"
    When an attacker writes that ciphertext into the database row for handle "vault://acme/password/other-secret"
    And the operator calls vault.get with handle "vault://acme/password/other-secret"
    Then the Vault Agent supplies Associated Data "vault://acme/password/other-secret" to the XChaCha20-Poly1305 decrypt call
    And AEAD verification fails because the Poly1305 authentication tag does not match
    And the Vault Agent returns an error without returning any plaintext material
    And an Audit Entry with op "get", outcome "error", and denial_reason "ad_binding_mismatch" is appended

  Scenario: PutSecret with value_format=utf8 stores plaintext bytes after AEAD encryption
    When the operator calls vault.put with the following parameters
      | field        | value                       |
      | name         | api-token                   |
      | category     | token                       |
      | sensitivity  | medium                      |
      | value        | ghp_AAABBBCCC111222333      |
      | value_format | utf8                        |
    Then the Vault Agent interprets the value string as raw UTF-8 bytes
    And the Private Blob contains the UTF-8 encoded bytes encrypted with XChaCha20-Poly1305
    And the Secret is persisted with handle "vault://acme-backend/token/api-token"
    And an Audit Entry with op "put" and outcome "allow" is appended

  Scenario: PutSecret with value_format=base64 decodes bytes before AEAD encryption
    When the operator calls vault.put with the following parameters
      | field        | value                               |
      | name         | signing-key                         |
      | category     | key                                 |
      | sensitivity  | high                                |
      | tags         | [{key: env, value: prod}]           |
      | value        | dGVzdC1iaW5hcnktcGF5bG9hZA==        |
      | value_format | base64                              |
    Then the Vault Agent base64-decodes the value string to obtain the raw binary bytes
    And the Private Blob contains the decoded binary bytes encrypted with XChaCha20-Poly1305
    And the Secret is persisted with handle "vault://acme-backend/key/signing-key"
    And an Audit Entry with op "put" and outcome "allow" is appended

  Scenario: PutSecret rejects missing value_format field with 400
    When the operator calls vault.put with the following parameters
      | field       | value         |
      | name        | my-token      |
      | category    | token         |
      | sensitivity | medium        |
      | value       | s3cr3t        |
    Then the Vault Agent rejects the request with error "schema_validation_failed"
    And the error message identifies "value_format" as a required missing field
    And no Secret is persisted to SQLite
