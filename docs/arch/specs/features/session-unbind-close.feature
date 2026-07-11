Feature: Session unbind close
  As an MCP client
  I want DELETE /v1/sessions to clear ephemeral session state
  So that tokens and tunnels do not leak after disconnect

  Scenario: Close clears use-tokens and reports counts
    Given an open session with use-tokens and tempfiles
    When the client DELETEs /v1/sessions/{session_id}
    Then closed is true
    And use_tokens_revoked and tempfiles_scheduled_for_cleanup are reported

  Scenario: Namespace binding survives close
    Given a namespace bound for the session
    When the client closes the session
    Then the namespace binding remains durable
