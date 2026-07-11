Feature: Init passphrase enroll
  As an operator
  I want init to enroll Argon2id passphrase wrap of the Master Key
  So that unseal can use passphrase without a separate enroll step

  Scenario: Init with passphrase enrolls fallback
    Given a new vault init ceremony
    When InitVaultCommand runs with passphrase set
    Then passphrase params and master wrap are stored in the keychain
    And init still returns vault_id and recovery material

  Scenario: Init without passphrase skips enroll
    Given a new vault init ceremony
    When InitVaultCommand runs with no passphrase and no MERKLE_MASTER_PASSPHRASE
    Then no passphrase wrap is enrolled
