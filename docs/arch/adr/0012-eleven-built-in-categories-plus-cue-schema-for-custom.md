---
status: accepted
date: 2026-05-22
deciders: [farchanjo]
consulted: []
informed: []
---

# 0012. Eleven Built-In Categories Plus CUE Schema for Custom Categories

## Context and Problem Statement

Every Secret belongs to a Category that defines its shape: which
fields are public (searchable metadata), which are private (encrypted
blob fields), what type constraints apply, and which Proxy Tools are
appropriate. Without a category system, the vault is a generic blob
store with no ability to reason about what kind of credential it
holds or how to operate it safely.

The Category must also support user extensibility: teams have
specialized credential types (hardware tokens, API keys with scoped
sub-keys, SAML certificates) that do not fit any standard category.
Custom categories must be validated against a declared schema so that
ill-formed secrets cannot be stored.

The alias resolution requirement prevents fragmentation: if one user
calls a category `api-key` and another calls it `api_key`, they should
resolve to the same canonical category.

## Decision Drivers

* Closed built-in enum prevents typos and ensures consistent
  Proxy Tool routing; the vault can safely switch on category to
  select the correct SSH Bridge, HTTP Bridge, or OTP generator.
* Extensibility without forking: custom categories must be expressible
  without modifying the vault binary.
* CUE schemas provide type-safe validation with a compile-tested
  definition language; they are already the schema language used
  across the spec (see `.specconfig.yml`).
* Alias resolution: common alternative spellings and short-forms must
  map to the canonical built-in name so that Handles are stable.
* Similarity warning: if a custom category name is suspiciously
  similar to a built-in (edit distance <= 2), the vault emits a
  warning at `vault.put` time to prevent accidental shadowing.
* FTS5 integration: the category field is indexed as a public
  metadata column (see
  [0013-fts5-on-public-metadata-fields-only.md](0013-fts5-on-public-metadata-fields-only.md)).

## Considered Options

* Option A: Eleven built-in categories with CUE schema extension
  and alias resolution
* Option B: Fully open string category with no schema enforcement
* Option C: Fixed closed enum with no extensibility
* Option D: JSON Schema for category definitions

## Decision Outcome

Chosen option: "Option A: Eleven built-in categories with CUE schema
extension", because the built-in set covers the overwhelming majority
of developer credential types, CUE provides type-safe extensibility
consistent with the rest of the spec toolchain, and alias resolution
+ similarity warnings prevent accidental divergence.

Built-in categories:

| Category | Default Sensitivity | Primary Proxy Tool |
|---|---|---|
| `ssh` | high | `vault.ssh.exec` |
| `password` | high | `vault.spawn` |
| `token` | medium | `vault.http.request` |
| `env` | medium | `vault.spawn` |
| `cert` | high | `vault.write_tempfile` |
| `key` | high | `vault.write_tempfile` |
| `database` | high | `vault.spawn` |
| `note` | low | `vault.reveal` |
| `otp` | medium | `vault.totp.generate` |
| `cloud` | high | `vault.spawn` |
| `gpg` | high | `vault.write_tempfile` |

Custom categories are declared in
`docs/arch/schemas/secret_storage/categories/<name>.cue` and
loaded by the vault at startup. A custom category schema must
declare: `public_fields`, `private_fields`, `default_sensitivity`,
and `allowed_proxy_tools`.

Aliases are declared in
`docs/arch/schemas/secret_storage/category_aliases.cue` and map
alternative names to canonical names at parse time.

### Consequences

* Good, because Proxy Tool routing is safe: the vault switches on
  the resolved category, and the built-in enum guarantees exhaustive
  match.
* Good, because CUE validation at `vault.put` time catches schema
  violations before any data is persisted.
* Good, because alias resolution keeps Handles stable even if the
  user uses non-canonical spelling; the canonical name is always
  stored.
* Good, because similarity warnings prevent accidental custom
  category creation (e.g., `ssh_key` when `ssh` was intended).
* Bad, because adding a new built-in category requires a vault
  binary update; operators who need a new built-in sooner must use
  a custom category temporarily.
* Bad, because CUE requires familiarity; operators writing custom
  categories must learn basic CUE syntax. Mitigated by providing
  example schemas in `docs/arch/schemas/secret_storage/categories/`.

## Pros and Cons of the Options

### Option A: Eleven built-in + CUE extension

* Good: type-safe built-in routing; extensible without binary change.
* Good: alias resolution; similarity warnings.
* Good: CUE consistent with the rest of the spec toolchain.
* Bad: CUE learning curve for custom category authors.

### Option B: Fully open string category

* Good: zero friction; any string accepted.
* Bad: Proxy Tool routing cannot be safe (no exhaustive match on
  open string).
* Bad: typos create orphaned secrets with no proxy tool routing.
* Bad: FTS5 index contains arbitrary unvalidated strings.

### Option C: Fixed closed enum, no extensibility

* Good: simplest implementation; no schema tooling required.
* Bad: any credential type not in the built-in list cannot be stored
  with schema validation; operators resort to storing it as `note`,
  losing all type semantics.
* Bad: adding new categories requires a binary release.

### Option D: JSON Schema for category definitions

* Good: widely understood; many tooling options.
* Bad: JSON Schema is not the schema language of the rest of the
  spec; mixing two schema languages adds toolchain complexity.
* Bad: JSON Schema cannot express the CUE-native constraints already
  used in identity, audit, and policy schemas.

## Validation

* Category routing test: store one secret per built-in category;
  invoke the canonical Proxy Tool for each; assert correct execution.
* Alias resolution test: store a secret with `category = "api-key"`;
  assert stored canonical category is `token` (or the declared alias
  target); assert Handle uses canonical name.
* Similarity warning test: attempt to create category `sssh`; assert
  warning is emitted referencing built-in `ssh`.
* Custom CUE validation test: write a minimal custom category schema;
  attempt to store a secret missing a required private field; assert
  `vault.put` rejects with schema error.

## More Information

* CUE language reference: `https://cuelang.org/docs/`.
* Related: [0007-handle-default-exposure-model.md](0007-handle-default-exposure-model.md)
* Related: [0013-fts5-on-public-metadata-fields-only.md](0013-fts5-on-public-metadata-fields-only.md)
* Related: [0017-llm-as-composer-no-foreign-keys-between-secrets.md](0017-llm-as-composer-no-foreign-keys-between-secrets.md)
