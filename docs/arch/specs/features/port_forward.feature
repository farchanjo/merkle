Feature: TCP port-forward via SSH tunnel

  The vault.ssh.port_forward MCP Tool establishes a long-lived TCP tunnel
  using an SSH subprocess that binds a local port and forwards connections
  to a remote host:port pair. The SSH private key never crosses the MCP
  transport; it is materialised in a mode-0600 tempfile inside the agent
  process, passed to the SSH subprocess via -i, and revoked when the tunnel
  closes. A UuidV7 session_id is returned so the operator can later revoke
  the tunnel. Per ADR-0023 the slash-command gate from ADR-0011 applies when
  the SSH key has sensitivity=high.

  Background:
    Given the Vault Agent is in Unsealed State
    And an ssh Secret with Handle "vault://acme-backend/ssh/bastion-prod" exists in namespace "acme-backend"
    And that Secret has category "ssh", sensitivity "medium", and host "bastion.prod.acme.io"

  Scenario: Port forward succeeds with valid SSH Handle
    Given the vault is unsealed and the Use Token resolves to a valid ssh-key
    When the operator invokes PortForward with local_port=8080 remote_host=db.internal remote_port=5432
    Then a tokio child process for "ssh -L 8080:db.internal:5432 bastion.prod.acme.io" is spawned
    And a session_id is returned
    And an Audit Entry with op "port_forward" and outcome "allow" is appended

  Scenario: Port forward denied without slash_command for sensitivity=high SSH key
    Given the SSH Handle has sensitivity=high
    And operator_confirmation.slash_command=false
    When PortForward is invoked
    Then the Vault Agent denies with denial_reason "missing_slash_command"
    And no child process is spawned

  Scenario: Port forward fails when vault is sealed
    Given the Vault Agent is in Sealed State
    When PortForward is invoked
    Then the Vault Agent rejects the request with error "vault sealed"
    And no child process is spawned

  Scenario: vault.port_forward via MCP returns session_id and local_addr
    Given the vault is unsealed and the SSH Handle has sensitivity=low
    And operator_confirmation.slash_command=true
    When the MCP client calls vault.port_forward with local_port=8080 remote_host=db.internal remote_port=5432
    Then the tool returns ToolOutput with session_id and local_addr "127.0.0.1:8080"
    And the underlying PortForwardCommand spawned a tokio::process Child
    And an Audit Entry with op "port_forward" outcome "allow" is appended
