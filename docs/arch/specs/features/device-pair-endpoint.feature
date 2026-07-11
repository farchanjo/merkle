Feature: Device pair endpoint
  Scenario: Pair enrolls a device
    Given the vault is Unsealed
    When the operator POSTs /v1/devices with class software
    Then the response status is 201
    And GET /v1/devices includes the new device_id
