# Privacy Threat Model (LINDDUN) — Merkle

Merkle primarily stores **secrets and credentials**, not end-user PII catalogs.
Privacy risks still arise from metadata, audit trails, materializations, and
logs. STRIDE system threats live in `stride-analysis.md` (same directory /
`docs/arch/threat-model/`).

## Data classes

| Class | Examples | Sensitivity |
|---|---|---|
| Secret plaintext | passwords, tokens, private keys | Critical |
| Public metadata | handle, tags, description, category | Low–Medium |
| Audit entries | op, outcome, handle, timestamps | Medium |
| Session / peer | UID, program path, namespace label | Low–Medium |
| Recovery material | age recovery key (shown once) | Critical |

## LINDDUN table

| ID | Category | Threat | Affected Data | Mitigation |
|---|---|---|---|---|
| P-01 | linking | Correlating ops over time reveals project structure and access patterns | Audit entries, handles | Local-only DB; mode 0600 paths; no remote audit by default |
| P-02 | identifying | cwd-bound labels may encode project paths | Namespace labels, cwd hash | Hash-derived labels; avoid PII in tags/descriptions |
| P-03 | non-repudiation | Strong audit desired; privacy tension if logs leave the machine | Audit HMAC chain | Operator-controlled export; no automatic cloud ship |
| P-04 | detecting | Materialized secrets detectable on disk while live | Tempfiles, FIFOs | 0600 files, short TTL, reaper sweep, single-use tokens |
| P-05 | data-disclosure | Plaintext or credentials in LLM context, logs, or SSRF targets | Secret plaintext, tokens | Handle default; `_meta` confirm; OOB; SSRF strict; log redaction |
| P-06 | unawareness | Operator may not notice backups or re-lock | Backup metadata, seal state | Doctor, status, launchd logs; documented idle default |
| P-07 | non-compliance | Old versions keep sensitive history | Secret version blobs | retain_count default 3; delete/rotate; no cloud retention |

## Residual risks

* Same-UID local attacker can read SQLite if the agent is sealed but the DB is
  not OS-encrypted — full-disk encryption is an operator responsibility.
* Empty `allowed_consumers` does not isolate processes (ADR-0015 A6).
* Recovery key printed at init must be stored offline by the operator.

## Related documents

* `docs/arch/threat-model/stride-analysis.md`
* `docs/arch/threat-model/trust-boundaries.md`
* `docs/arch/threat-model/attack-surface.md`
* SECURITY.md (disclosure process)
