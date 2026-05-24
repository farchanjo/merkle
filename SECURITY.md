# Security Policy

---

## Supported versions

| Version | Supported |
|:---|:---:|
| `main` branch (pre-alpha) | Yes |
| Any tagged release | Will be assessed on release |

Only the `main` branch receives security fixes while the project is in pre-alpha.
Once the first stable release (`v0.1.0`) ships, this table will be updated with a
formal support window.

---

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

### Preferred channel

Send a private email to:

```
farchanjo@gmail.com
```

Subject line: `[SECURITY] Merkle — <brief summary>`

Include:

1. Description of the vulnerability and affected component(s).
2. Steps to reproduce or a proof-of-concept (even a rough sketch is helpful).
3. Potential impact and your assessment of severity (Critical / High / Medium / Low).
4. Your name or handle for attribution in the hall of fame (optional).

### Alternative channel

Open a **confidential** merge request on GitLab if you have a repository account.
Mark it confidential before saving. This ensures the vulnerability is not visible
publicly until a fix is ready.

---

## Response SLA targets

| Milestone | Target |
|:---|:---|
| Initial acknowledgment | 48 hours after report receipt |
| Severity triage and initial assessment | 7 days |
| Mitigation for Critical / High | 30 days |
| Mitigation for Medium | 90 days |
| Mitigation for Low | Next regular release cycle |
| Public disclosure (coordinated) | After patch is released and users have had time to upgrade |

These are targets, not guarantees, for a pre-alpha project with a small team.
Critical vulnerabilities will be treated with urgency regardless of the published
SLA.

---

## Scope

The following are in scope for security reports:

- All Rust source code under `crates/` and `bin/`
- Rego policies under `docs/arch/policies/`
- MCP protocol contracts under `docs/arch/integrations/`
- Cryptographic design decisions documented in the ADRs (design flaws are in
  scope even if no code exists yet)
- Key hierarchy: Master Key, Vault Root Key, Namespace DEK, Recovery Key handling
- OOB Confirmation flow and Ed25519 signature verification (ADR-0011)
- Audit hash chain integrity (ADR-0009)
- Companion Socket authentication (PID check, process name allowlist)
- Backup encryption (`age` dual-recipient model, ADR-0006)

The following are out of scope:

- Third-party dependencies — run `cargo audit` for known CVEs in the dependency
  tree; report upstream to the crate maintainer.
- Vulnerabilities requiring physical access to the machine that is already running
  the vault agent (the threat model assumes the operator's machine is trusted).
- Social engineering or phishing attacks against operators.
- Denial-of-service attacks that require authenticated access to the Companion
  Socket.

---

## Threat model

The full STRIDE threat model with trust boundaries, data-flow diagrams, and
adversary profiles is maintained at:

```
docs/arch/threat-model/
```

Reviewers are encouraged to read it before submitting a report — your finding may
already be documented as an accepted risk, which will expedite triage.

---

## Cryptographic primitives

Merkle uses the following primitives; vulnerabilities in their design or in
Merkle's use of them are in scope:

| Primitive | Purpose | Reference |
|:---|:---|:---|
| XChaCha20-Poly1305 | Per-blob AEAD encryption | RFC 8439 extended-nonce variant |
| Argon2id | Master Key derivation from passphrase | RFC 9106 |
| BLAKE3 | Audit hash chain, key derivation | BLAKE3 paper |
| Ed25519 | OOB Confirmation signatures, Operator Attestation | RFC 8032 |
| X25519 | Recovery Key (`age` identity) | RFC 7748 |
| `age` | Backup encryption (dual recipient) | filippo.io/age |

---

## Hall of fame

Responsible disclosure contributors will be listed here with their permission.

*(No entries yet — this project is pre-alpha.)*
