Feature: Allowlisted spawn proxy
  Scenario: Spawn is not hard 501
    Given the vault is Unsealed
    When the operator calls POST /v1/proxy/spawn with an allowlisted command
    Then the response is not a hard 501 stub
