# Contributing to Merkle

Thank you for considering a contribution to Merkle. This document covers everything
you need to get from a fresh clone to a merged contribution.

---

## Code of Conduct

All contributors are expected to follow the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
By participating you agree to abide by its terms.

---

## Development workflow

### 1. Clone and build

```sh
git clone https://github.com/farchanjo/merkle.git
cd merkle
cargo build --release
```

The release binary is at `target/release/merkle`. No system-level runtime is
required; SQLite is bundled via `rusqlite`.

### 2. Run the test suite

```sh
just test          # cargo nextest run --all-features
just lint          # cargo clippy --all-targets --all-features
just fmt           # cargo fmt --all -- --check
```

All three must exit 0 before opening a merge request.

### 3. Run the spec validation gate

Every change that touches behavior — new MCP tool, changed schema, new policy
outcome, new CLI subcommand — must pass the full spec lane:

```sh
just spec          # spec validate --lane full
```

This runs CUE vet, Conftest (Rego), Vale prose linting, and TLC model checking.
See the [Spec-mode discipline](#spec-mode-discipline) section for what artifacts
to update before running this gate.

### 4. Run the doctor

```sh
just doctor        # merkle doctor (against the local dev vault)
```

Expected: all checks green. Fix any reported issues before submitting.

### 5. Open a merge request

- Push your branch to the repository.
- Open a merge request against `main`.
- Fill in the merge request description using the template provided.
- Address all review comments in new commits — do not force-push after the MR
  is open unless explicitly requested.

---

## Spec-mode discipline

Merkle uses a strict spec-as-source-of-truth discipline enforced by
[ADR-0018](docs/arch/adr/0018-full-coverage-validation-as-architectural-contract.md).
Every code change that introduces or modifies behavior MUST be accompanied by the
corresponding artifact updates under `docs/arch/`. The `spec validate --lane full`
gate in CI enforces this — a code-only change that breaks a Rego policy test or a
Gherkin scenario will fail CI.

| Change type | Required artifact update |
|:---|:---|
| New or modified MCP tool | CUE schema in `docs/arch/schemas/` + OpenAPI/AsyncAPI in `docs/arch/integrations/` |
| New acceptance behavior | Gherkin scenario in `docs/arch/specs/features/` + Cucumber test |
| New or changed policy gate | Rego file in `docs/arch/policies/` + policy test |
| Architectural decision | New MADR ADR in `docs/arch/adr/NNNN-<slug>.md` |
| Security-touching change | Updated STRIDE entries in `docs/arch/threat-model/` |
| New SLO | YAML in `docs/arch/slo/` |

If you are unsure whether your change is architectural, open a draft MR and ask in
the review. The default answer is: if in doubt, write an ADR.

### Adding a new ADR

1. Copy `docs/arch/adr/0000-template.md` to `docs/arch/adr/NNNN-<slug>.md` where
   `NNNN` is the next available four-digit number.
2. Set `status: proposed`, `date: YYYY-MM-DD`, `deciders: [your-handle]`.
3. Fill in all sections. Consulted and Informed may be empty lists.
4. Link related ADRs in **More Information**.
5. When the decision is finalized, update `status: accepted`.

---

## Commit message convention

Merkle follows Angular commit message format:

```
<type>(<scope>): <subject>

[optional body]

[optional footer: Fixes #N, Related !N]
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `ci`.

**Scope** is the bounded context or crate name: `identity`, `storage`,
`mediation`, `audit`, `backup`, `policy`, `mcp-adapter`, `cli`, `crypto`,
`keychain`, `agent`.

**Subject** is imperative mood, lowercase, no trailing period, ≤72 characters.

Examples:

```
feat(audit): add BLAKE3 hash chain to audit entries
fix(mediation): reject oob_ack without nonce verification
docs(arch): add ADR-0019 for tempfile reaping strategy
test(policy): add Rego unit tests for cross-namespace deny
```

Breaking changes must include `BREAKING CHANGE:` in the footer and bump the
CHANGELOG.

---

## Pull request checklist

Before marking a merge request as ready for review, confirm each item:

- [ ] `just doctor` exits 0
- [ ] `just test` exits 0 (all `cargo nextest` tests pass)
- [ ] `just lint` exits 0 (no `clippy` warnings)
- [ ] `just fmt` exits 0 (code is formatted)
- [ ] `just spec` exits 0 (`spec validate --lane full`)
- [ ] New ADR added, or existing ADR amended, if the change is architectural
- [ ] Gherkin scenario added to `docs/arch/specs/features/` if the change
  introduces a new acceptance behavior
- [ ] Cucumber test exercises the new Gherkin scenario
- [ ] Rego policy updated and unit-tested if the change touches a policy gate
- [ ] Threat model updated in `docs/arch/threat-model/` if the change
  introduces or modifies a security boundary
- [ ] CHANGELOG.md updated under `## [Unreleased]` with a brief bullet
- [ ] DCO sign-off present on all commits (`git commit -s`)

---

## Branching strategy

Merkle uses trunk-based development with short-lived feature branches:

- `main` is always releasable.
- Feature branches are named `<type>/<scope>/<short-description>`, for example
  `feat/audit/add-hmac-signature` or `fix/mediation/oob-nonce-validation`.
- Branches live for the duration of one MR and are deleted on merge.
- Do not accumulate multiple unrelated changes in a single branch.

Long-running experiment branches may use `exp/<description>` and are exempt from
the merge SLA but must not diverge more than 14 days before rebasing.

---

## Developer Certificate of Origin

By contributing to this project, you certify that:

1. The contribution was created in whole or in part by you and you have the right
   to submit it under the Apache-2.0 license.
2. The contribution is based upon previous work that, to the best of your
   knowledge, is covered under an appropriate open source license and you have
   the right under that license to submit that work with modifications.
3. The contribution was provided directly to you by some other person who
   certified (1) or (2) and you have not modified it.
4. You understand and agree that this project and the contribution are public
   and that a record of the contribution (including all personal information you
   submit with it, including your sign-off) is maintained indefinitely and may be
   redistributed consistent with this project or the open source license(s) involved.

To sign off, add `-s` to your `git commit` invocations:

```sh
git commit -s -m "feat(audit): add chain verifier integration test"
```

This appends `Signed-off-by: Your Name <your@email.com>` to the commit message.

---

## Getting help

- Open an issue for bug reports and feature requests.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do not open a
  public issue.
- For architectural questions, open a draft MR with a proposed ADR and request
  review.
