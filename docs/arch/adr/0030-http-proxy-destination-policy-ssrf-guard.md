---
status: accepted
date: 2026-07-10
deciders: [farchanjo]
consulted: []
informed: []
---

# ADR-0030 — Strict HTTPS public-host egress policy with connect-time DNS revalidation

## Context and Problem Statement

Proxy tools (`vault_http_request`, `vault_http_download`, `vault_http_upload` and
the matching Companion Socket `/v1/proxy/http/*` endpoints) attach vault-held
credentials to caller-supplied URLs and perform egress from the **agent** process
(ADR-0024 amendment 2026-07-10). Without a destination policy, a prompt-injected
or compromised client can steer those credentials at:

* cloud metadata endpoints (e.g. `169.254.169.254`);
* loopback / link-local / private / CGNAT management planes;
* non-HTTPS cleartext sinks;
* DNS-rebinding targets that resolve public at check time and private at connect.

Peer-credential auth and namespace policy do not address destination choice.
SSRF defenses must live at the external-services adapter, before Authorization
headers are attached, and again at connect time.

## Decision Drivers

* Fail closed: ambiguous or unresolvable destinations deny.
* No credential attach before policy pass.
* Close DNS rebind TOCTOU between URL validation and TCP connect.
* Production must never silently use a permissive policy.
* Tests need a deliberate escape hatch for loopback HTTP mocks.

## Considered Options

1. **Trust the URL string only** (scheme/host allowlist without IP class checks).
2. **Pre-flight IP class checks only** (no connect-time revalidation).
3. **Strict pre-flight + connect-time revalidation** (`DestinationPolicy` +
   `ValidatingDnsResolver`). Chosen.
4. **External proxy / egress gateway** only. Deferred; may complement later.

## Decision Outcome

Chosen option: "Option 3: Strict pre-flight + connect-time revalidation",
because HTTP proxy tools attach vault credentials to caller-supplied URLs and
must deny non-public and non-https destinations both before credential attach
and again at connect time (DNS-rebind TOCTOU). Implemented in
`crates/merkle-adapter-external-services`:

### Pre-flight: `DestinationPolicy::strict()` (default)

`DestinationPolicy::default()` is `strict()`. Before credentials attach:

1. URL must parse.
2. Scheme must be `https` only.
3. Host must be present.
4. Every resolved address (or literal IP) must pass `is_forbidden_ip` rejection
   for: loopback, link-local (incl. 169.254 metadata), private (RFC1918), CGNAT,
   multicast/broadcast/unspecified, IPv6 ULA/link-local, mapped-forbidden, and
   additional closed gaps maintained in `destination_policy.rs` (e.g. NAT64 /
   documentation / reserved ranges as implemented).

### Connect-time: `ValidatingDnsResolver`

The shared HTTPS client installs a DNS resolver that re-applies the same
`is_forbidden_ip` predicate at connect time. If resolution yields only forbidden
addresses, the connect fails closed — closing the TOCTOU window between
pre-flight resolution and socket establishment.

### Test-only: `DestinationPolicy::permissive()`

`permissive()` performs no validation and is `#[doc(hidden)]` for integration
tests (e.g. wiremock on loopback HTTP). **Production composition roots MUST
call `strict()` or rely on `Default`.** Shipping `permissive()` in agent wiring
is a contract violation.

### Placement

Policy enforcement runs in the agent-side HTTP proxy path (not in `merkle-mcp`),
consistent with ADR-0024 amendment (proxy I/O in the agent).

### Consequences

* Good, because classic SSRF against metadata and private nets is blocked before
  credentials attach.
* Good, because connect-time revalidation closes DNS-rebind TOCTOU.
* Good, because `Default` is strict, reducing misconfiguration risk.
* Bad, because legitimate `http://` or loopback targets need test-only
  `permissive()` or a future operator exception (not provided today).
* Bad, because DNS resolution adds cost on the HTTP proxy hot path (accepted).
* Neutral, because SSH proxy destinations are out of scope; peer-cred and
  `allowed_consumers` remain separate layers.

## Validation

* Unit tests in `destination_policy.rs` cover forbidden classes and
  `permissive` loopback.
* Agent composition uses strict policy for live HTTP adapter construction.
* Threat model SSRF rows reference this ADR.

## More Information

* `crates/merkle-adapter-external-services/src/destination_policy.rs`
* `crates/merkle-adapter-external-services/src/dns_guard.rs` (or resolver module
  as named in tree)
* ADR-0024 (proxy locus)
* `docs/arch/threat-model/attack-surface.md`
* OpenAPI `/v1/proxy/http/*` error mapping
