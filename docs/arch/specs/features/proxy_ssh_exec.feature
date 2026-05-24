Feature: Executing a remote command via the SSH proxy tool

  The vault.ssh.exec MCP Tool invokes a command on a remote host using the SSH Bridge
  without exposing the private key to the MCP transport. The Vault Agent resolves the
  Handle to its Private Blob internally, injects key material into the SSH Bridge, and
  returns only filtered stdout, stderr, and exit code to the LLM. Use Tokens are
  consumed once and expire after 60 seconds. Tempfiles or FIFOs materializing key
  material are cleaned up when the session closes. Operator Confirmation is not required
  for proxy execution at sensitivity levels low or medium.

  Background:
    Given the Vault Agent is in Unsealed State
    And an ssh Secret with Handle "vault://acme-backend/ssh/db-prod" exists in namespace "acme-backend"
    And that Secret has category "ssh", sensitivity "medium", and host "db.prod.acme.io"
    And the Namespace Policy rate limit for "use_token_resolves" is 100 per minute

  Scenario: Execute uptime using the Handle without the private key crossing the MCP transport
    When the LLM calls vault.ssh.exec with handle "vault://acme-backend/ssh/db-prod" and command "uptime"
    Then the Vault Agent resolves the Handle to its Private Blob internally via the Proxy Executor
    And the SSH Bridge injects the private key into the SSH session without returning it to the MCP transport
    And the SSH Bridge establishes a connection to "db.prod.acme.io" on port 22
    And the command "uptime" executes on the remote host
    And the MCP response contains stdout, stderr, and exit_code from the remote execution
    But the MCP response does not contain the private key, passphrase, or any private material
    And an Audit Entry with op "use", handle "vault://acme-backend/ssh/db-prod", and outcome "allow" is appended
    And the Audit Entry records the caller_program field identifying the MCP client process that initiated the request

  Scenario: Execution fails when the Handle resolves to a non-ssh category
    Given an ssh Secret with Handle "vault://acme-backend/password/db-admin" exists with category "password"
    When the LLM calls vault.ssh.exec with handle "vault://acme-backend/password/db-admin" and command "whoami"
    Then the Vault Agent rejects the request with error "category_mismatch"
    And the error message states that vault.ssh.exec requires category "ssh" but received category "password"
    And no SSH Bridge connection is initiated
    And an Audit Entry with op "use", outcome "deny", and denial_reason "rejected_category_mismatch" is appended

  Scenario: Execution fails when the rate limit for use_token_resolves is exceeded
    Given 100 use_token_resolves operations have been performed in the current minute
    When the LLM calls vault.ssh.exec with handle "vault://acme-backend/ssh/db-prod" and command "df -h"
    Then the Vault Agent rejects the request with error "rate_limit_exceeded"
    And the error response includes the rate limit class "use_token_resolves" and the reset time
    And no SSH Bridge connection is initiated
    And an Audit Entry with op "use", outcome "deny", and denial_reason "rejected_rate_limit" is appended

  Scenario: Support jump-host chaining via jump_host_handle field
    Given an ssh Secret with Handle "vault://acme-backend/ssh/bastion-prod" exists for host "bastion.prod.acme.io"
    And the ssh Secret "vault://acme-backend/ssh/db-prod" declares "jump_host_handle" as "vault://acme-backend/ssh/bastion-prod"
    When the LLM calls vault.ssh.exec with handle "vault://acme-backend/ssh/db-prod" and command "hostname"
    Then the Vault Agent resolves both Handles internally via the Proxy Executor
    And the SSH Bridge connects to "bastion.prod.acme.io" first using the bastion private key
    And tunnels from the bastion to "db.prod.acme.io" using the db private key
    And both private keys are injected inside the agent without crossing the MCP transport
    And the MCP response contains the output of "hostname" from "db.prod.acme.io"

  Scenario: Tempfile or FIFO is cleaned up after the SSH session closes
    Given the SSH Bridge requires a key Tempfile at an opaque token path under "/run/merkle/sessions/<opaque-token>/key" with mode 0600
    When the SSH Bridge completes the remote command and closes the session
    Then the Vault Agent removes the Tempfile at the opaque token path
    And no key material remains on the filesystem after cleanup
    And if the MCP Session terminates unexpectedly, the orphan Tempfile is reaped at next agent boot using the session_id index

  Scenario: Operator Confirmation is NOT required for proxy execution at sensitivity medium or below
    Given the Secret "vault://acme-backend/ssh/db-prod" has sensitivity "medium"
    When the LLM calls vault.ssh.exec with handle "vault://acme-backend/ssh/db-prod" and command "ps aux"
    Then the Vault Agent executes the command without prompting for Operator Confirmation
    And no OOB Confirmation request is sent
    And the Reveal Policy is not consulted because no plaintext is returned to the MCP transport
    And the command result is returned directly to the LLM
