---
status: accepted
date: 2026-07-10
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0032 — Security profiles as policy-default bundles

## Context and Problem Statement

Operators need a single vocabulary for vault threat posture at init and in
runtime config. Spreading OOB thresholds, rate limits, consumer defaults, device
class, unseal preconditions, and idle guidance across unrelated knobs produces
inconsistent deployments and doc drift (e.g. ADR-0021 text using `"low"` while
the type system uses `relaxed`).

The closed enum already exists in code and CUE as
`relaxed | balanced | paranoid` (`merkle-types::SecurityProfile`). This ADR
records the architectural contract for that enum as **policy-default bundles**,
how they seed `NamespacePolicy`, how they interact with idle re-lock (ADR-0031),
and what remains operator-configured.

## Decision Drivers

* One closed vocabulary for threat posture.
* Safe enough defaults for laptop dogfood (`balanced`).
* Explicit harsher posture (`paranoid`) with mlock / OOB expectations.
* No silent marketing of "paranoid" without documenting residual gaps.
* Align init OpenAPI/CUE with runtime types (`relaxed`, not `low`).

## Considered Options

1. **Free-form TOML policy only** — no named profiles.
2. **Profiles as documentation tables only** — no code enum.
3. **Closed enum profiles seeding NamespacePolicy + config posture.** Chosen.

## Decision Outcome

Chosen option: "Option 3: Closed enum profiles seeding NamespacePolicy + config
posture", because a single vocabulary (`relaxed|balanced|paranoid`) keeps init,
runtime config, and domain defaults aligned without free-form partial hardening.

### Closed enum

```text
SecurityProfile = relaxed | balanced | paranoid
```

Ordering for comparisons: `Paranoid > Balanced > Relaxed`. Unknown strings fail
parse. Init and config MUST use these identifiers; the label `low` is not a
profile name (fix any remaining CUE/OpenAPI drift to `relaxed`).

### What a profile seeds

`NamespacePolicy::defaults_for(profile)` (and init ceremony application of the
chosen profile) sets coherent defaults including:

| Concern | relaxed | balanced (default) | paranoid |
|---|---|---|---|
| Reveal `allowed` | true | true | **false** (kill-switch; no reveal until policy override) |
| Reveal OOB threshold (`require_oob_above`) | High | High | Medium (stricter floor if reveals re-enabled) |
| Slash required for reveal | false (relaxed default) | true | true (when reveals re-enabled) |
| Rate limits | higher ceilings | medium | tighter |
| `allowed_consumers` globs | `["*"]` | empty (socket skips gate; ADR-0015 A6) | empty (same) |
| Unseal / mlock posture | mlock not required | mlock preferred | mlock required when enforced by unseal gates |
| Idle timeout **recommendation** | 1800s | 1800s | 300s |

Exact field values are those implemented in
`merkle-domain-policy-permissions` (`RevealPolicy::default_*`,
`RateLimit::default_*`, `AllowedConsumers::default_*`, etc.). This ADR forbids
introducing a fourth profile without a new ADR.

### Runtime config

`[security] security_profile` selects the posture for agent-level gates that
read the profile (e.g. unseal preconditions). Optional
`[security] idle_lock_timeout_secs` overrides the idle supervisor (ADR-0031).

**Current composition note (honest):** the agent applies
`DEFAULT_IDLE_LOCK_TIMEOUT = 1800` when `idle_lock_timeout_secs` is unset, and
does **not** automatically map `paranoid → 300`. Operators who choose paranoid
SHOULD set `idle_lock_timeout_secs = 300` (or lower) until a future change wires
profile→timeout in the composition root. README tables that state "paranoid =
5 min idle" are **operator configuration guidance**, not a silent automatic
mapping unless code is updated in the same commit as that claim.

### Consumer allowlists

* `relaxed` defaults to `["*"]` (any process path matches).
* Empty `allowed_consumers` under balanced/paranoid does **not** mean process
  isolation at the socket (ADR-0015 Amendment 6 skips the gate when empty).
  Profiles that need process allowlists require explicit path-aware globs after
  init.

### Init ceremony

ADR-0021 init may accept `security_profile` in the request body. Values must be
the closed enum above. Recovery recipient and dual-wrap VRK rules remain in
ADR-0021 / ADR-0006.

### Consequences

* Good, because posture is a single closed vocabulary across domain, config,
  and docs.
* Good, because defaults bundle OOB, rate limits, and related gates together.
* Bad, because empty `allowed_consumers` under balanced/paranoid does not imply
  process isolation (ADR-0015 Amendment 6) — operators must set globs.
* Bad, because idle timeout is not auto-mapped from profile today; paranoid
  operators must set `idle_lock_timeout_secs` until composition wires mapping.
* Neutral, because post-init profile changes require explicit policy updates,
  not a silent rewrite of all namespaces.

## Validation

* Type parse tests reject unknown profiles.
* `NamespacePolicy::defaults_for` unit tests lock OOB thresholds per profile.
* Config `deny_unknown_fields` keeps typo'd profile keys loud.
* Init CUE/OpenAPI use `relaxed|balanced|paranoid` only.

## More Information

* `crates/merkle-types/src/security_profile.rs`
* `crates/merkle-domain-policy-permissions/src/namespace_policy.rs`
* ADR-0011, ADR-0015 A6, ADR-0021, ADR-0031
* `docs/arch/schemas/policy_permissions/security_profile.cue`
* `docs/arch/domain/policy-permissions.md`
