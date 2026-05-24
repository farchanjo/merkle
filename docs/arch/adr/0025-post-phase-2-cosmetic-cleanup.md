---
status: accepted
date: 2026-05-24
deciders: [farchanjo]
consulted: []
informed: []
---

# 0025. Post-Phase-2 Cosmetic Cleanup

## Context and Problem Statement

ADR-0024 (MCP Adapter Consumes Companion Socket Client) closed the Phase-2
refactor that wired `crates/merkle-adapter-mcp` through
`crates/merkle-companion-client` and eliminated the direct `AppContext`
dependency. A live smoke test run against the running `merkle-agent` daemon
immediately after the merge surfaced five discrete bugs, catalogued below as
#1–#6 (Bug #4 is intentionally out of scope — see note below).

Three bugs are functional regressions (#1, #2, #3): they prevent the user
from completing canonical workflows (list namespaces, cross-session secret
references, and audit chain verification) without manual workarounds. Two
bugs are lower-severity documentation or UX issues (#5, #6): they produce
confusing but non-blocking output or ambiguous docstrings.

Bug #4 — `vault.doctor` failing the OOB notifier check — is a macOS
notification-permission platform requirement, not a code bug. No binary
change is necessary; the operator must grant notification permission. This
is tracked as a platform-setup task and is explicitly out of scope for this
ADR.

## Decision Drivers

* **Developer ergonomics**: `merkle list` and `merkle put` are the two most
  common CLI workflows; both must work without error after an initial bind.
* **Spec-to-code alignment**: `GET /v1/namespaces` is documented in the
  Companion Socket OpenAPI contract to return the full Namespace list; the
  missing `Storage` port method means the implementation silently returns an
  empty list instead.
* **No `null` in defined boolean fields**: `chain_valid` in the
  `GET /v1/audit?verify_chain=true` response is specified as `boolean` in
  the OpenAPI contract; returning `null` violates the schema and breaks
  callers that pattern-match on the value.
* **CLI clarity**: an incorrect "already unsealed" message after a
  successful seal-to-unsealed transition misleads the operator about vault
  state.
* **Handle URI stability**: a handle that encodes the raw secret name instead
  of the bound namespace label changes across sessions and is not usable as a
  stable cross-session reference, which contradicts ADR-0008 §Handle URI
  structure.

## Bug Catalogue

| ID | Summary | Root-cause module | Fix module | Spec touchpoint |
|----|---------|-------------------|-----------|-----------------|
| #1 | Handle URI segment encodes secret name instead of bound namespace label | `crates/merkle-application/src/commands/put_secret.rs` — handle generation reads raw name rather than the resolved namespace label from session state | `put_secret.rs` — source bound namespace label from session state when constructing the handle URI | ADR-0008 §Handle URI structure |
| #2 | `Storage::list_namespaces()` port method missing — `GET /v1/namespaces` returns empty list when label filter is `None` | `crates/merkle-application/src/queries/list_namespaces.rs:44-47` — `None` label branch returns empty `Vec` because the `Storage` port trait has no `list_namespaces()` method | Extend `Storage` port trait with `list_namespaces() -> Vec<Namespace>`; provide implementation in `crates/merkle-adapter-sqlite/src/namespaces.rs`; wire the `None` branch in `list_namespaces.rs` | OpenAPI `/v1/namespaces` GET — documented as returning the full Namespace list |
| #3 | `vault.audit.query?verify_chain=true` returns `chain_valid: null` | `crates/merkle-application/src/queries/query_audit.rs` — `verify_chain` flag is read from the request but `ChainVerifier::verify()` is never called; the response field is left unset (`None` serialises as `null`) | `query_audit.rs` — invoke `ChainVerifier::verify()` when `verify_chain=true` and populate the response `chain_valid` boolean from the result | ADR-0009 §Validation + ADR-0009 Chain Verifier role; OpenAPI `/v1/audit` `chain_valid` response field |
| #5 | CLI `merkle unseal` prints "ok: vault was already unsealed" even when the transition is sealed → unsealed | `bin/merkle-cli/src/commands/unseal.rs` — response branch does not distinguish `already_unsealed: false` from `already_unsealed: true`; the same success message is printed for both transitions | `unseal.rs` — branch on `UnsealResponse.already_unsealed`: print "ok: vault unsealed" when `false`, "ok: vault was already unsealed" when `true` | UX — no spec contract; aligns with ADR-0021 §Unseal ceremony observable state |
| #6 | `vault.bind` MCP tool docstring implies `cwd_hash` is an internal leakage; operators misinterpret it as an MCP parameter | `crates/merkle-adapter-mcp/src/tools/identity.rs::vault_bind` — docstring does not explain that BLAKE3 of `std::env::current_dir()` is the canonical CWD-bound namespace identity per ADR-0008, not a leakage of internal state | Add docstring clarification and cross-reference ADR-0008 in `identity.rs::vault_bind`; no behavioral change | ADR-0008 §Binding algorithm, step 3 |

## Considered Options

* **Option A**: Fix all five in-scope bugs (#1, #2, #3, #5, #6) in targeted
  PRs. Skip Bug #4 (OOB notifier) as a platform-setup task.
* **Option B**: Defer all five bugs to future PRs, gated behind a dedicated
  Phase-3 milestone.
* **Option C**: Redesign the Handle URI scheme entirely to use a stable
  opaque token rather than a namespace-label composite, eliminating Bug #1 at
  the schema level.

## Decision Outcome

Chosen option: **Option A — fix all five in-scope bugs; skip #4**.

Option B is rejected because Bugs #1, #2, and #3 block real operator
workflows today: the CLI cannot list namespaces after bind, handle URIs are
unstable across sessions, and audit chain verification is silently broken.
Deferring these to a Phase-3 milestone would leave Phase-2 in a state that
fails the smoke test every session.

Option C is rejected as out of scope for a cleanup ADR. Redesigning the
Handle URI scheme is a functional change that requires its own ADR, CUE
schema update, and migration plan. The fix for Bug #1 (source bound
namespace label from session state) is consistent with the existing ADR-0008
scheme and does not require a schema change.

### Consequences

* Good, because `merkle list` and `merkle put` work end-to-end immediately
  after `merkle bind` without any workaround.
* Good, because `vault.audit.query?verify_chain=true` returns a correct
  boolean `chain_valid` that callers can rely on; the spec-to-code gap is
  closed.
* Good, because handle URIs are stable across sessions — a handle created in
  one Claude Code window is usable in another window bound to the same
  namespace label.
* Good, because `merkle unseal` prints an accurate status message that
  reflects the actual vault-state transition.
* Bad, because extending the `Storage` port trait with `list_namespaces()`
  is a breaking change for any external implementors of that trait. No
  external implementors exist in the current workspace tree; the breakage
  surface is internal only.

## Validation

Each bug fix lands with a TDD test authored before the fix (impl-guard
requires a failing test artifact prior to any source-code edit).

1. **Bug #1**: regression test in `bin/merkle-cli/tests/cli_smoke.rs` —
   bind a namespace, put a secret, assert handle URI segment equals the bound
   namespace label, not the secret name.
2. **Bug #2**: unit test in `crates/merkle-adapter-sqlite/src/namespaces.rs`
   — insert two Namespaces with distinct labels; call `list_namespaces()`;
   assert both are returned.
3. **Bug #3**: integration test in `crates/merkle-application` — create three
   audit entries; call `query_audit` with `verify_chain=true`; assert
   `chain_valid` is `true` (not `null`); tamper with entry 2 hash; re-query;
   assert `chain_valid` is `false`.
4. **Bug #5**: unit test in `bin/merkle-cli/src/commands/unseal.rs` — mock
   `UnsealResponse { already_unsealed: false }`; assert output contains
   "vault unsealed" but not "already unsealed".
5. **Bug #6**: no behavioral test required; `cargo doc --document-private-items`
   must render the updated docstring with the ADR-0008 cross-reference.

`spec validate` must remain at all lanes green (9/9) throughout every PR in
this batch.

After all PRs merge, re-run the live smoke test sequence in order:

```
merkle doctor
merkle bind [label]
merkle put [secret]
merkle list
merkle describe [handle]
vault.audit.query?verify_chain=true
```

Assert all six steps succeed with accurate output and `chain_valid: true`.

## More Information

* [ADR-0008](0008-cwd-bound-namespace-with-overrides.md) — canonical
  CWD-bound namespace identity; handle URI structure; `vault.bind` behaviour.
  See Implementation Note — 2026-05-24 appended to that ADR for the MCP
  adapter's materialisation of `cwd_hash` internally via BLAKE3 of
  `std::env::current_dir()`.
* [ADR-0009](0009-merkle-style-audit-hash-chain.md) — BLAKE3 hash chain;
  Chain Verifier role; `chain_valid` semantic. See Implementation Note —
  2026-05-24 appended to that ADR for the mandatory `ChainVerifier::verify()`
  call on `verify_chain=true` requests.
* [ADR-0024](0024-mcp-adapter-consumes-companion-socket-client.md) — the
  Phase-2 refactor whose live integration smoke test surfaced these five bugs.
  See Follow-up — 2026-05-24 appended to that ADR.
* [ADR-0021](0021-init-vault-bootstrap-ceremony.md) — unseal ceremony
  observable state; basis for Bug #5 UX fix.
* Bug #4 (OOB notifier doctor fail on macOS) is tracked as a platform-setup
  task in the operations runbook; it requires granting macOS notification
  permission to `merkle-agent`. No code change is needed.
* `crates/merkle-application/src/commands/put_secret.rs` — Bug #1 root cause.
* `crates/merkle-application/src/queries/list_namespaces.rs:44-47` — Bug #2
  root cause.
* `crates/merkle-application/src/queries/query_audit.rs` — Bug #3 root cause.
* `crates/merkle-adapter-sqlite/src/namespaces.rs` — Bug #2 fix target.
* `bin/merkle-cli/src/commands/unseal.rs` — Bug #5 fix target.
* `crates/merkle-adapter-mcp/src/tools/identity.rs` — Bug #6 fix target.
