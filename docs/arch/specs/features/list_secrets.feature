Feature: Listing Secrets in a Namespace

  The vault_list MCP Tool returns Public Metadata for all Secrets visible to the
  current session. Private Blob fields are never included in list responses.
  Results support filtering by Category, Tag key:value pairs, and free-text FTS5
  search. Responses are ordered by created_at descending and support cursor-based
  pagination. The LLM may reason about the listed metadata to select the correct
  Handle for subsequent Proxy Tool invocations.

  Background:
    Given the Vault Agent is in Unsealed State
    And the Namespace "acme-backend" with id "0192ac11-7000-7000-8000-000000000010" is bound for the session
    And the following Secrets exist in namespace "acme-backend"
      | handle                                         | category | sensitivity | tags                                                                        | created_at              |
      | vault://acme-backend/ssh/bastion-prod          | ssh      | medium      | [{key: env, value: prod}, {key: role, value: bastion}]                      | 2026-05-01T10:00:00Z    |
      | vault://acme-backend/ssh/bastion-staging       | ssh      | medium      | [{key: env, value: staging}, {key: role, value: bastion}]                   | 2026-05-02T11:00:00Z    |
      | vault://acme-backend/token/deploy-token-prod   | token    | high        | [{key: env, value: prod}, {key: project, value: acme}]                      | 2026-05-03T09:00:00Z    |
      | vault://acme-backend/password/db-admin         | password | high        | [{key: env, value: prod}, {key: role, value: dba}]                          | 2026-05-04T08:00:00Z    |
      | vault://acme-backend/note/architecture-notes   | note     | low         | [{key: project, value: acme}]                                               | 2026-05-05T14:00:00Z    |

  Scenario: List all Secrets in the Namespace returns metadata only and no Private Blob
    When the operator calls vault_list with no filters
    Then the MCP response contains exactly 5 entries
    And each entry contains Handle, category, sensitivity, tags, name, and created_at
    And no entry contains a private_blob field or any decrypted key material
    And results are ordered by created_at descending with "vault://acme-backend/note/architecture-notes" first
    And an Audit Entry with op "list" and outcome "allow" is appended to the Audit Log

  Scenario: Filter by Category returns only matching Secrets
    When the operator calls vault_list with filter "category=ssh"
    Then the MCP response contains exactly 2 entries
    And both entries have category "ssh"
    And the entries are "vault://acme-backend/ssh/bastion-staging" and "vault://acme-backend/ssh/bastion-prod"
    And no token, password, or note Secrets appear in the response
    And no Private Blob is included in any entry

  Scenario: Filter by Tag key:value query returns only matching Secrets
    When the operator calls vault_list with filter "tag=env:prod"
    Then the MCP response contains exactly 3 entries
    And all returned Secrets have tag "env:prod" in their tag set
    And the entries are
      | vault://acme-backend/password/db-admin       |
      | vault://acme-backend/token/deploy-token-prod |
      | vault://acme-backend/ssh/bastion-prod        |
    And Secrets with tags containing only {key: env, value: staging} or {key: project, value: acme} alone are excluded

  Scenario: Free-text FTS5 search returns ranked results
    Given the FTS5 Index is built over the Public Metadata fields of all Secrets
    When the operator calls vault_list with query "bastion"
    Then the FTS5 Index returns matches ranked by relevance
    And the response contains the two ssh Secrets whose names include "bastion"
    And results are ordered by FTS5 rank descending, with higher-relevance matches first
    And no Private Blob or encrypted material is included in the search response

  Scenario: List response excludes private material in all response shapes
    When the operator calls vault_list with filter "category=password"
    Then the response contains the Secret "vault://acme-backend/password/db-admin"
    And the response fields for that entry are limited to name, Handle, category, sensitivity, tags, created_at, updated_at, expires_at, and version
    But the response does not contain any of the following fields: private_blob, private_key, password, credential, secret_value
    And the MCP transport log contains no plaintext credential for that Secret

  Scenario: Pagination by created_at desc with cursor returns correct page
    Given the Namespace contains 5 Secrets ordered by created_at descending
    When the operator calls vault_list with "limit=3" and no cursor
    Then the response contains the 3 most recently created Secrets
    And the response includes a next_cursor token pointing to the 4th entry
    When the operator calls vault_list with the returned next_cursor and "limit=3"
    Then the response contains the remaining 2 Secrets
    And the response does not include a next_cursor token indicating the final page
