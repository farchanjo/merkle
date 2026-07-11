Feature: Corpus health green
  As a Merkle maintainer
  I want the arch corpus to pass native speckit validate with zero findings
  So that CI and local gates stay trustworthy without waiver debt

  Scenario: Validate is clean
    Given a clean repository checkout with dual-tree docs/arch and doc/arch
    When the operator runs speckit validate
    Then the command exits with code 0
    And the report shows zero findings

  Scenario: Check accepts Angular history
    Given commits use Angular subjects at most 72 characters
    When the operator runs speckit check
    Then the git prerequisite reports ok
