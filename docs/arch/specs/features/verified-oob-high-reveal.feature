Feature: Verified OOB high reveal
  Scenario: Forged oob_ack is insufficient
    Given a High sensitivity secret
    When reveal is called with slash_command true and oob_ack true without OOB resolution
    Then the reveal is denied
  Scenario: Approved OOB unlocks high reveal
    Given a High sensitivity secret and an approving OOB notifier
    When reveal is called with slash_command true
    Then plaintext is returned
