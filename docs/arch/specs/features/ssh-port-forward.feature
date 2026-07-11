Feature: SSH port forward product enablement
  Scenario: Port forward endpoint is implemented
    Given the vault is Unsealed
    When the operator calls POST /v1/proxy/ssh/port-forward
    Then the response is not a hard 501 capability stub
