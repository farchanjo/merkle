Feature: Passphrase unseal socket
  Scenario: Correct passphrase unseals without keychain master
    Given passphrase fallback is enrolled
    When the operator POSTs /v1/agent/unseal with passphrase
    Then the vault is Unsealed with method argon2id_passphrase
  Scenario: Wrong passphrase is rejected
    Given passphrase fallback is enrolled
    When the operator POSTs a wrong passphrase
    Then unseal fails authentication
