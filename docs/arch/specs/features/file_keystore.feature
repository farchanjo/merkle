Feature: File-Backed Keystore for Headless Contexts
  As a Merkle vault operator running in a headless or CI environment
  I want a file-backed keystore that persists secrets encrypted with age
  So that the agent functions correctly without access to an OS-native keychain

  # ADR-0022: FileKeystoreAdapter — age-encrypted file backend for headless contexts.
  # Tests are tagged with @file_keystore for BDD step filtering.

  Background:
    Given a temporary directory for the keystore file
    And a FileKeystoreAdapter opened at the temporary path with passphrase "test-passphrase"

  @file_keystore
  Scenario: File keystore stores and retrieves Master Key in headless context
    When I store 32 secret bytes for service "dev.fapp.merkle" account "master-v1"
    Then I can retrieve the same 32 bytes for service "dev.fapp.merkle" account "master-v1"
    And the keystore file exists on disk

  @file_keystore
  Scenario: File keystore decrypts existing keystore on agent restart
    Given I have stored 32 bytes for service "dev.fapp.merkle" account "master-v1" using the adapter
    When I open a new FileKeystoreAdapter from the same path with the same passphrase
    Then retrieving service "dev.fapp.merkle" account "master-v1" returns the same 32 bytes

  @file_keystore
  Scenario: File keystore aborts when passphrase is wrong
    Given I have stored 32 bytes for service "dev.fapp.merkle" account "master-v1" using the adapter
    When I attempt to open a new FileKeystoreAdapter from the same path with passphrase "wrong-passphrase"
    Then the open call returns a KeychainError::Backend describing a decrypt failure
    And no data is accessible

  @file_keystore
  Scenario: Auto backend falls back from OS to file when OS keychain reports PersistenceFailed
    Given a MockKeychainAdapter configured to return PersistenceFailed for service "dev.fapp.merkle" account "master-v1"
    And a FileKeystoreAdapter as the fallback adapter
    When the auto-selection logic attempts to store via the OS adapter
    And the OS adapter returns KeychainError::PersistenceFailed
    Then the auto-selection logic retries the store via the FileKeystoreAdapter
    And the FileKeystoreAdapter store succeeds
    And a subsequent retrieve via the FileKeystoreAdapter returns the stored bytes
