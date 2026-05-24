Feature: Revealing a Secret's plaintext

  The vault.reveal MCP Tool returns the plaintext of a Secret's Private Blob to the
  MCP transport. Because revealed material enters the LLM context window, this operation
  requires operator_confirmation.slash_command=true in all cases. For sensitivity=high
  Secrets, operator_confirmation.oob_ack=true is additionally required through a channel
  separate from the MCP transport. Reveals where slash_command=false are unconditionally
  denied regardless of sensitivity. Every reveal attempt, whether approved or rejected,
  is recorded in the Audit Log.

  Operator Confirmation is modelled with two independent boolean flags:
    slash_command: true  — the client verified a /merkle-reveal slash command
    oob_ack:       true  — an OOB Confirmation channel (desktop-notif, terminal-prompt,
                           or localhost-confirm) was acknowledged by the operator

  Background:
    Given the Vault Agent is in Unsealed State
    And the following Secrets exist in namespace "acme-backend"
      | handle                                         | category | sensitivity |
      | vault://acme-backend/note/architecture-notes   | note     | low         |
      | vault://acme-backend/token/deploy-token-prod   | token    | medium      |
      | vault://acme-backend/password/db-admin         | password | high        |
    And the Reveal Policy for namespace "acme-backend" has allowed=true, require_oob_above="high"
    And a Companion Device is enrolled with an Ed25519 keypair stored in the OS Keychain under service "dev.fapp.merkle.companion"

  Scenario: Reveal sensitivity=low Secret via slash command without OOB Confirmation
    Given the operator issues the Slash Command "/merkle-reveal vault://acme-backend/note/architecture-notes"
    And the client sets operator_confirmation with slash_command=true and oob_ack=false
    When the MCP Adapter invokes vault.reveal with handle "vault://acme-backend/note/architecture-notes"
    Then the Vault Agent evaluates sensitivity "low" against OOB threshold "high"
    And sensitivity "low" is below the threshold so oob_ack is not required
    And the Vault Agent decrypts the Private Blob using the Namespace DEK
    And the plaintext content of "vault://acme-backend/note/architecture-notes" is returned in the MCP response
    And an Audit Entry with op "reveal", handle "vault://acme-backend/note/architecture-notes", and outcome "allow" is appended

  Scenario: Reveal sensitivity=medium Secret via slash command without OOB Confirmation
    Given the operator issues the Slash Command "/merkle-reveal vault://acme-backend/token/deploy-token-prod"
    And the client sets operator_confirmation with slash_command=true and oob_ack=false
    When the MCP Adapter invokes vault.reveal with handle "vault://acme-backend/token/deploy-token-prod"
    Then the Vault Agent evaluates sensitivity "medium" against OOB threshold "high"
    And sensitivity "medium" is below the threshold so oob_ack is not required
    And the Vault Agent decrypts the Private Blob using the Namespace DEK
    And the plaintext content of "vault://acme-backend/token/deploy-token-prod" is returned in the MCP response
    And an Audit Entry with op "reveal", handle "vault://acme-backend/token/deploy-token-prod", and outcome "allow" is appended

  Scenario: Reveal sensitivity=high Secret requires both slash_command and oob_ack
    Given the operator issues the Slash Command "/merkle-reveal vault://acme-backend/password/db-admin"
    And the client sets operator_confirmation with slash_command=true and oob_ack=false
    When the MCP Adapter invokes vault.reveal with handle "vault://acme-backend/password/db-admin"
    Then the Vault Agent determines sensitivity is "high" and initiates an OOB Confirmation request
    And the OOB Confirmation request is delivered via a desktop notification on the operator's machine
    When the operator acknowledges the OOB Confirmation within the timeout window
    Then the client sets oob_ack=true and oob_channel="desktop-notif"
    And the Vault Agent decrypts the Private Blob using the Namespace DEK
    And the plaintext content of "vault://acme-backend/password/db-admin" is returned in the MCP response
    And an Audit Entry with op "reveal", handle "vault://acme-backend/password/db-admin", outcome "allow", and note "oob_confirmed" is appended

  Scenario: Reveal sensitivity=high denied when slash_command=true but oob_ack=false
    Given the operator issues the Slash Command "/merkle-reveal vault://acme-backend/password/db-admin"
    And the client sets operator_confirmation with slash_command=true and oob_ack=false
    When the MCP Adapter invokes vault.reveal with handle "vault://acme-backend/password/db-admin"
    And the Vault Agent sends an OOB Confirmation request via desktop notification
    And 60 seconds elapse without operator acknowledgment
    Then the OOB Confirmation times out and oob_ack remains false
    And the Vault Agent denies the reveal with error "oob_confirmation_timeout"
    And no decryption is performed
    And an Audit Entry with op "reveal", handle "vault://acme-backend/password/db-admin", outcome "deny", and denial_reason "rejected_oob_timeout" is appended

  Scenario: LLM-initiated reveal without a slash command is denied regardless of sensitivity
    Given the LLM constructs a vault.reveal call with handle "vault://acme-backend/token/deploy-token-prod"
    And the operator_confirmation has slash_command=false and oob_ack=false
    When the MCP Adapter invokes vault.reveal with the constructed call
    Then the Vault Agent rejects the request with error "operator_confirmation_required"
    And the error message states that vault.reveal requires slash_command=true
    And no decryption is performed
    And no plaintext material is returned to the MCP transport
    And an Audit Entry with op "reveal", handle "vault://acme-backend/token/deploy-token-prod", outcome "deny", and denial_reason "rejected_no_confirmation" is appended

  Scenario: Reveal sensitivity=high denied when only oob_ack=true but slash_command=false
    Given the operator_confirmation has slash_command=false and oob_ack=true and oob_channel="terminal-prompt"
    When the MCP Adapter invokes vault.reveal with handle "vault://acme-backend/password/db-admin"
    Then the Vault Agent rejects the request with error "operator_confirmation_required"
    And the error message states that vault.reveal requires slash_command=true
    And no decryption is performed
    And an Audit Entry with op "reveal", handle "vault://acme-backend/password/db-admin", outcome "deny", and denial_reason "rejected_no_confirmation" is appended

  Scenario: Audit Log records every reveal attempt regardless of outcome
    Given three reveal attempts have been made in sequence
      | handle                                          | slash_command | oob_ack | oob_channel    | outcome | denial_reason            |
      | vault://acme-backend/note/architecture-notes    | true          | false   | n/a            | allow   |                          |
      | vault://acme-backend/token/deploy-token-prod    | false         | false   | n/a            | deny    | rejected_no_confirmation |
      | vault://acme-backend/password/db-admin          | true          | false   | n/a            | deny    | rejected_oob_timeout     |
    When the operator queries the Audit Log filtered by op "reveal"
    Then exactly 3 Audit Entries with op "reveal" are returned
    And each entry contains timestamp, session_id, namespace_id, handle, outcome, and chain hashes
    And the Hash Chain is intact across all three entries

  Scenario: Reveal denied when OobResolution signature missing
    Given the operator issues the Slash Command "/merkle-reveal vault://acme-backend/password/db-admin"
    And the client sets operator_confirmation with slash_command=true and oob_ack=true and oob_channel="desktop-notif"
    And the OobResolution payload has outcome "approved" but device_signature is null
    When the MCP Adapter invokes vault.reveal with handle "vault://acme-backend/password/db-admin"
    Then the Vault Agent evaluates the OobResolution and detects that device_signature is null
    And the Vault Agent rejects the request with error "oob_signature_missing"
    And no decryption is performed
    And an Audit Entry with op "reveal", handle "vault://acme-backend/password/db-admin", outcome "deny", and denial_reason "oob_signature_missing" is appended

  Scenario: Reveal denied when OobResolution signature invalid
    Given the operator issues the Slash Command "/merkle-reveal vault://acme-backend/password/db-admin"
    And the client sets operator_confirmation with slash_command=true and oob_ack=true and oob_channel="desktop-notif"
    And the OobResolution payload has outcome "approved" and device_signature is a non-null byte sequence
    And the device_signature does not verify against the enrolled Companion Device Ed25519 public key
    When the MCP Adapter invokes vault.reveal with handle "vault://acme-backend/password/db-admin"
    Then the Vault Agent computes signature verification using the enrolled Companion Device public key
    And the verification fails because the signature was not produced by the enrolled device keypair
    And the Vault Agent rejects the request with error "oob_signature_invalid"
    And no decryption is performed
    And an Audit Entry with op "reveal", handle "vault://acme-backend/password/db-admin", outcome "deny", and denial_reason "oob_signature_invalid" is appended

  Scenario: Reveal-only category note rejects proxy tool invocations but supports reveal
    Given the Secret "vault://acme-backend/note/architecture-notes" has category "note"
    When the LLM calls vault.ssh.exec with handle "vault://acme-backend/note/architecture-notes"
    Then the Vault Agent rejects the request with error "proxy_tool_not_supported_for_category"
    And the error message states that category "note" supports reveal only and does not support Proxy Tool invocation
    When the client sets operator_confirmation with slash_command=true and oob_ack=false
    And the operator issues "/merkle-reveal vault://acme-backend/note/architecture-notes"
    Then the reveal succeeds and returns the plaintext note content to the MCP transport

  Scenario: Reveal succeeds via signed_config_flag JWT for non-Claude client
    Given the operator has enrolled a JWT attestation Ed25519 key in the OS Keychain
    And the MCP client supplies a valid JWT with kid="merkle-operator-attestation" matching the challenge_id
    And sensitivity is "medium"
    When vault.reveal is called with operator_confirmation { slash_command: false, oob_ack: false, signed_config_flag: <jwt> }
    Then the JWT signature verifies against the enrolled public key
    And the Reveal Authorization Decision allows the reveal
    And the plaintext is returned to the MCP transport
    And an Audit Entry with op "reveal" outcome "allow" attestation "jwt" is appended

  Scenario: Reveal denied when JWT signature fails verification
    Given an enrolled JWT attestation key
    And the MCP client supplies a JWT signed by a different key
    When vault.reveal is called with signed_config_flag set
    Then the Vault Agent denies with denial_reason "invalid_signed_config_flag"
    And no plaintext is returned

  Scenario: Reveal denied when JWT exp is past
    Given an enrolled JWT attestation key
    And the JWT exp claim is 1 second in the past
    When vault.reveal is called
    Then the Vault Agent denies with denial_reason "signed_config_flag_expired"

  Scenario: Reveal denies on AD binding mismatch
    Given the Vault Agent is in Unsealed State
    And the database contains a corrupted Private Blob for handle "vault://acme-backend/password/db-admin"
    And the corrupted blob was encrypted with Associated Data "vault://acme-backend/password/other-secret" rather than the row's own Handle URI
    And the operator issues the Slash Command "/merkle-reveal vault://acme-backend/password/db-admin"
    And the client sets operator_confirmation with slash_command=true and oob_ack=true
    When the MCP Adapter invokes vault.reveal with handle "vault://acme-backend/password/db-admin"
    Then the Vault Agent supplies Associated Data "vault://acme-backend/password/db-admin" to the XChaCha20-Poly1305 decrypt call
    And the Poly1305 authentication tag verification fails because the stored Associated Data does not match the row Handle URI
    And the Vault Agent aborts decryption without loading any plaintext material into memory
    And the Vault Agent returns an error to the caller
    And an Audit Entry with op "reveal", outcome "error", and denial_reason "ad_binding_mismatch" is appended
