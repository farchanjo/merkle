Feature: Buffered SSH shell
  Scenario: Shell endpoint is not 501
    Given the vault is Unsealed
    When the operator calls POST /v1/proxy/ssh/shell
    Then the response is not a hard 501 stub
