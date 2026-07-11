Feature: Session Bind Idempotency and State Atomicity

  vault_bind associates the current MCP session with a named Namespace. The
  binding is idempotent at the storage layer: calling vault_bind with a label
  that already exists in storage must resolve the existing Namespace and
  succeed, not attempt a conflicting insert. Within a single MCP session the
  binding is still enforced as "at most once" — a second vault_bind call in the
  same session returns AlreadyBound regardless of the label supplied.

  SessionState.namespace_bound and SessionState.namespace_id must always agree.
  A vault_bind call that fails at the Companion Socket layer must not leave the
  session in a half-bound state (namespace_bound=true, namespace_id=None).

  Background:
    Given the Vault Agent is in Unsealed State
    And the namespace label "reconnect-test" does not yet exist in storage

  Scenario: First bind of a new label creates the namespace and succeeds
    When the operator calls vault_bind with label "reconnect-test"
    Then the MCP response contains a namespace_id
    And the MCP response contains a session_id
    And the MCP response contains namespace_label "reconnect-test"
    And the vault_list tool returns success (not NamespaceNotBound)
    And an Audit Entry with op "bind" and outcome "allow" is appended to the Audit Log

  Scenario: Second call from a new MCP session with the same label is idempotent success
    Given a previous MCP session already bound namespace label "reconnect-test"
    And that MCP session has since terminated
    When a new MCP session calls vault_bind with label "reconnect-test"
    Then the MCP response contains the same namespace_id as the first session
    And the MCP response status is success (not AlreadyBound, not server error)
    And the vault_list tool in the new session returns success (not NamespaceNotBound)
    And exactly one namespace row with label "reconnect-test" exists in storage

  Scenario: vault_bind then vault_list succeeds within the same session
    When the operator calls vault_bind with label "reconnect-test"
    And the operator calls vault_list with no filters
    Then the vault_list call succeeds and returns a result set (not NamespaceNotBound)

  Scenario: vault_bind then vault_search succeeds within the same session
    When the operator calls vault_bind with label "reconnect-test"
    And the operator calls vault_search with query "test"
    Then the vault_search call succeeds and returns a result set (not NamespaceNotBound)

  Scenario: Second vault_bind in the same session returns AlreadyBound
    When the operator calls vault_bind with label "reconnect-test"
    Then the first bind returns success
    When the operator calls vault_bind again with label "other-label"
    Then the MCP response is AlreadyBound (-32008)
    And the session remains bound to "reconnect-test"
    And vault_list continues to return success (not NamespaceNotBound)

  Scenario: vault_bind failure at Companion Socket layer does not poison session state
    Given the Vault Agent Companion Socket is unreachable
    When the operator calls vault_bind with label "reconnect-test"
    Then the MCP response is AgentUnreachable (-32100)
    And the session namespace_id remains unset (None)
    When the Vault Agent Companion Socket becomes reachable again
    And the operator calls vault_bind with label "reconnect-test"
    Then the second bind returns success (not AlreadyBound)
    And the session namespace_id is set to the resolved namespace_id
    And vault_list returns success (not NamespaceNotBound)
