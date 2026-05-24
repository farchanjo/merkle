Feature: OS Keychain Adapter
  As the Merkle vault agent
  I want to store and retrieve secrets in the OS-native keychain
  So that the Master Key is protected by platform security controls

  Background:
    Given a keychain adapter backed by the OS keychain or an in-memory mock

  Scenario: Store and retrieve a secret round-trip
    When I store secret bytes for service "dev.fapp.merkle" account "master-v1"
    Then I can retrieve the same bytes for service "dev.fapp.merkle" account "master-v1"

  Scenario: List accounts under a service
    Given I have stored secrets for accounts "master-v1" and "master-v2" under service "dev.fapp.merkle"
    When I list accounts for service "dev.fapp.merkle"
    Then the result contains "master-v1" and "master-v2"

  Scenario: Delete an account removes it from the index
    Given I have stored a secret for service "dev.fapp.merkle" account "master-v1"
    When I delete the entry for service "dev.fapp.merkle" account "master-v1"
    Then listing service "dev.fapp.merkle" does not include "master-v1"
    And retrieving service "dev.fapp.merkle" account "master-v1" returns NotFound

  Scenario: Delete a non-existent account returns NotFound
    When I delete service "dev.fapp.merkle" account "absent-key"
    Then the result is KeychainError::NotFound

  Scenario: Account index is updated on store (idempotent)
    Given I have stored a secret for service "svc" account "acct"
    When I store the same account again for service "svc" account "acct"
    Then listing service "svc" contains "acct" exactly once

  Scenario: Secrets are stored as raw bytes without UTF-8 assumption
    When I store 32 arbitrary bytes (including non-UTF-8 sequences) for service "dev.fapp.merkle" account "master-v1"
    Then I retrieve exactly those 32 bytes back
