Feature: Audit remote HMAC webhook
  As a compliance operator
  I want each durable audit entry POSTed to a remote URL with HMAC
  So that SIEM sinks can verify integrity without blocking the vault

  Scenario: Webhook fires after successful audit commit
    Given MERKLE_AUDIT_WEBHOOK_URL is configured
    When audit_commit persists an entry
    Then a POST is attempted with Content-Type application/json
    And X-Merkle-Audit-HMAC covers the JSON body

  Scenario: Missing URL skips remote delivery
    Given no audit webhook URL is set
    When audit_commit succeeds
    Then no HTTP request is issued
    And local audit remains durable
