Feature: Audit Chain integrity verification

  The Audit Log is an append-only sequence of Audit Entries where each entry stores
  a two-field hash chain: current_hash = BLAKE3(serialize(entry_without_hashes) || prev_hash)
  and prev_hash linking to the predecessor's current_hash. This design, inspired by
  Ralph Merkle's tree construction, ties content and chain linkage in a single field. The Chain Verifier validates the entire
  chain end-to-end, detecting any entry mutation, reordering, or removal. HMAC Signatures
  over individual entries enable authenticated delivery to a remote webhook. The Audit Log
  supports structured queries by op, namespace, time range, and outcome. A Cross-Env
  Warning is emitted and recorded when Secrets tagged with different env:* values are
  accessed in the same MCP Session.

  Background:
    Given the Vault Agent is in Unsealed State
    And the Audit Log contains 1000 Audit Entries chained with Blake3
    And each Audit Entry stores fields: id, timestamp, session_id, namespace_id, op, handle, reason, outcome, denial_reason, caller_pid, current_hash, prev_hash
    And the Hash Chain is intact from entry 1 through entry 1000

  Scenario: Chain verifier passes on an intact Audit Log
    When the operator calls merkle doctor or vault_audit_verify
    Then the Chain Verifier reads all 1000 entries in order from the Audit Log
    And for each entry it recomputes current_hash as BLAKE3(serialize(entry_without_hashes) || prev_hash) and verifies it matches the stored current_hash
    And for each entry it verifies the stored prev_hash equals the current_hash of the preceding entry
    And entry 1 has prev_hash equal to the genesis sentinel "0000000000000000000000000000000000000000000000000000000000000000"
    And the Chain Verifier reports outcome "intact" with entry count 1000
    And no Audit Entry is appended for a successful verification (verification is read-only)

  Scenario: Tampering with any single entry breaks the chain at that point
    Given entry 500 has had its "outcome" field changed from "success" to "failure" after original insertion
    When the Chain Verifier processes the Audit Log
    Then the recomputed current_hash for entry 500 does not match the stored current_hash of entry 500
    And the Chain Verifier reports outcome "broken_at_entry" with broken_at_id matching the UUIDv7 of entry 500
    And all entries from 500 through 1000 are flagged as "unverifiable" because the chain is broken at the tampered point
    And entries 1 through 499 are reported as "verified"
    And the Chain Verifier exits with a non-zero status code indicating integrity failure

  Scenario: Removing an entry invalidates the chain from that index forward
    Given entry 250 has been deleted from the Audit Log by a direct database modification
    When the Chain Verifier processes the Audit Log
    Then the entry previously at index 251 now has a prev_hash referencing the hash of the deleted entry 250
    And the prev_hash of the current index-250 entry (formerly index 251) does not match the current_hash of the current index-249 entry
    And the Chain Verifier reports outcome "broken_at_entry" with broken_at_id matching the UUIDv7 of the removed entry 250 and note "entry_removed"
    And all entries from index 250 onward are flagged as "unverifiable"
    And entries 1 through 249 are reported as "verified"

  Scenario: HMAC sync delivers signed Audit Entries to a remote webhook
    Given a remote webhook URL "https://audit.acme.io/merkle-events" is configured in config.toml
    And a per-vault HMAC key is stored securely in the OS Keychain
    When a new Audit Entry is appended to the Audit Log
    Then the remote sync worker computes an HMAC Signature over the Audit Entry payload using the per-vault HMAC key
    And the sync worker delivers the Audit Entry and HMAC Signature to "https://audit.acme.io/merkle-events" via HTTPS POST
    And the delivery is retried with exponential backoff if the webhook returns a non-2xx response
    And the HMAC Signature allows the webhook receiver to authenticate the event without a shared database
    And the delivery outcome is recorded in a separate sync_log table but does not append a new Audit Entry to the main chain

  Scenario: Query Audit Log by op, namespace, time range, and outcome
    When the operator calls vault_audit_query with filters
      | filter_field | filter_value                          |
      | op           | reveal                                |
      | namespace_id | 0192ac11-7000-7000-8000-000000000010  |
      | from         | 2026-05-01T00:00:00Z                  |
      | to           | 2026-05-22T23:59:59Z                  |
      | outcome      | allow                                 |
    Then the Audit Log is queried using the SQLite index on (op, namespace_id, timestamp)
    And only Audit Entries matching all specified filters are returned
    And each returned entry contains id, timestamp, session_id, namespace_id, op, handle, outcome, and chain hashes
    And no Private Blob or plaintext credential material is included in the query response
    And the results are ordered by timestamp ascending

  Scenario: Cross-Env Warning is recorded when env:prod and env:staging are accessed in the same session
    Given the current MCP Session has id "0192ac11-7000-7000-8000-000000000050"
    And the operator accesses Secret "vault://acme-backend/ssh/bastion-prod" tagged "env:prod" in this session
    And the operator then accesses Secret "vault://acme-backend/ssh/bastion-staging" tagged "env:staging" in the same session
    When the Vault Agent processes the second access
    Then the Vault Agent detects that the current session contains accesses to both "env:prod" and "env:staging" tag values
    And a Cross-Env Warning Audit Entry is appended with op "cross_env_warning", session_id "0192ac11-7000-7000-8000-000000000050", and note "env:prod + env:staging in same session"
    And the Cross-Env Warning is a forensic marker only and does not block the second access
    And the Audit Entry is included in the Hash Chain as a regular entry chained from the previous hash
