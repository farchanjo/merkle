Feature: BM25-Ranked Full-Text Search over Public Metadata

  The vault_search MCP Tool and the fts_query parameter of vault_list
  execute a weighted BM25 query over the FTS5 virtual table secrets_fts.
  The index covers five public metadata columns: name (weight 10.0),
  tags (weight 5.0), description (weight 3.0), category (weight 2.0),
  and namespace_label (weight 1.0). Results are returned in order of
  descending relevance (most-negative BM25 score first). Each result
  carries a numeric score, a 1-based page rank, and per-field highlight
  snippets. Private blob fields never appear in the index or in highlights.
  See ADR-0027 for the authoritative weight vector and query template.

  Background:
    Given the Vault Agent is in Unsealed State
    And the Namespace "acme-backend" with id "0192ac11-7000-7000-8000-000000000010" is bound for the session
    And the FTS5 Index is built over the public metadata fields of all Secrets in namespace "acme-backend"

  Scenario: Name-match ranks above description-match for the same query term
    Given the following Secrets exist in namespace "acme-backend"
      | handle                                              | name                  | category | description                                              | tags                         |
      | vault://acme-backend/ssh/github-deploy-key          | github-deploy-key     | ssh      | deploy key for CI pipelines                              | [{key: env, value: prod}]    |
      | vault://acme-backend/token/ci-pipeline-token        | ci-pipeline-token     | token    | GitHub token used for automated deployment workflows     | [{key: env, value: prod}]    |
      | vault://acme-backend/note/infrastructure-notes      | infrastructure-notes  | note     | notes about the github organization and repo permissions | [{key: project, value: acme}]|
    When the operator calls vault_search with query "github"
    Then the response contains all three matching Secrets
    And the Secret with name "github-deploy-key" has bm25_rank 1
    And the Secrets with name-match appear before the Secrets with description-match only
    And each result item contains a non-null numeric "score" field
    And each result item contains a "bm25_rank" integer starting at 1
    And no Private Blob or encrypted material is included in any result

  Scenario: Weighted BM25 prevents TF-stuffing from overriding name match
    Given the following Secrets exist in namespace "acme-backend"
      | handle                                          | name              | category | description                                                    | tags                      |
      | vault://acme-backend/token/deploy-token         | deploy-token      | token    | production token                                               | [{key: env, value: prod}] |
      | vault://acme-backend/note/deploy-notes          | deploy-notes      | note     | deploy deploy deploy deploy deploy deploy deploy deploy deploy  | [{key: project, value: x}]|
    When the operator calls vault_search with query "deploy"
    Then the Secret with name "deploy-token" has bm25_rank 1
    And the Secret with name "deploy-notes" does not have bm25_rank 1
    And the result for "deploy-token" has a more-negative score than the result for "deploy-notes"

  Scenario: Pagination preserves rank order across pages
    Given 15 Secrets exist in namespace "acme-backend" all matching query "acme" with varying name and description match strength
    When the operator calls vault_search with query "acme" limit 5 offset 0
    Then the response contains exactly 5 results
    And the response includes "has_more: true"
    And the response includes "total" equal to the count of all matching Secrets
    When the operator calls vault_search with query "acme" limit 5 offset 5
    Then no handle from the first page appears in the second page
    And the score of the last result on page 1 is less relevant than the score of the first result on page 2
    And bm25_rank values on page 2 begin at 1 (page-local, not global)

  Scenario: Highlight snippets are present and reference only public fields
    Given a Secret exists in namespace "acme-backend"
      | handle                                     | name              | category | description                                            | tags                      |
      | vault://acme-backend/ssh/bastion-prod-key  | bastion-prod-key  | ssh      | SSH key for the production bastion host at Latitude DC | [{key: env, value: prod}] |
    When the operator calls vault_search with query "bastion"
    Then the response for "vault://acme-backend/ssh/bastion-prod-key" contains a "highlights" array
    And at least one entry in "highlights" has field "name" with snippet containing "<b>bastion</b>"
    And at least one entry in "highlights" has field "description" with snippet containing "<b>bastion</b>"
    And no entry in "highlights" has field equal to any of: private_blob, ciphertext, nonce, aead_tag, associated_data
    And no snippet text contains any substring that appears in the encrypted private_blob of any Secret

  Scenario: Private fields never appear in highlights or search results
    Given a Secret "vault://acme-backend/ssh/prod-key" exists with private_blob encrypted value "SUPERSECRET_KEY_MATERIAL"
    When the operator calls vault_search with query "SUPERSECRET"
    Then the response contains zero results
    When the operator calls vault_search with query "prod"
    Then any matching results do not contain the string "SUPERSECRET_KEY_MATERIAL" in any response field
    And no result contains a "private_blob" field

  Scenario: FTS5 index reflects updated description after rotate
    Given a Secret "vault://acme-backend/token/old-token" exists with description "initial database credential"
    When the Secret is rotated with a new description "updated production oauth token"
    And the operator calls vault_search with query "initial"
    Then the Secret "vault://acme-backend/token/old-token" does not appear in results
    When the operator calls vault_search with query "oauth"
    Then the Secret "vault://acme-backend/token/old-token" appears in results
    And its highlight snippet for field "description" contains "<b>oauth</b>"

  Scenario: Porter stemming resolves inflected query terms
    Given a Secret "vault://acme-backend/token/auth-service-token" exists with description "authentication token for the authorization service"
    When the operator calls vault_search with query "authenticat"
    Then the Secret "vault://acme-backend/token/auth-service-token" appears in results
    When the operator calls vault_search with query "authoriz"
    Then the Secret "vault://acme-backend/token/auth-service-token" appears in results

  Scenario: Doctor check validates FTS5 schema column list
    When the operator calls vault_doctor with check "fts5_schema"
    Then the doctor response reports the fts5_schema check as "ok"
    And the reported column list is exactly "name, tags, description, category, namespace_label"
    And the reported weight vector is "10.0, 5.0, 3.0, 2.0, 1.0"
