# Quality Attribute Scenarios — Merkle

ISO/IEC 25010:2023 attributes (speckit closed set). Each row is measurable.

| ID | Attribute | Stimulus | Environment | Response | Measure |
|---|---|---|---|---|---|
| QS-01 | security | LLM issues `vault_reveal` without slash `_meta` | Unsealed agent, bound session | Tool denies; no plaintext returned | 100% denials in tests without `_meta` true |
| QS-02 | security | Truncate audit_entries and rebuild tail | Unsealed, HMAC key present | verify/doctor reports head or HMAC failure | Fail closed; never silent Intact |
| QS-03 | security | Proxy HTTP to link-local metadata IP | Strict DestinationPolicy | Reject before credential attach | Unit + adapter tests green |
| QS-04 | reliability | Process crash mid-audit commit | WAL SQLite | No entry without matching pinned head MAC | Atomic commit_audit_entry contract |
| QS-05 | reliability | Idle 1800s after last authed request | Unsealed agent | Agent seals via SealVaultCommand | Status shows sealed |
| QS-06 | performance-efficiency | vault_list under nominal namespace size | Unsealed, local socket | Completes within SLO budget | vault-list-latency-p95 indicator |
| QS-07 | performance-efficiency | Full chain verify on doctor | Unsealed, large audit log | Completes without hang | Doctor check returns |
| QS-08 | maintainability | Behavioral change required | Local workspace | Spec + code updated same train | Review checklist |
| QS-09 | flexibility | File keystore on headless CI | No OS keychain GUI | auto falls back to file; tests pass | lifecycle/e2e with file backend |
| QS-10 | interaction-capability | merkle doctor on sealed vault | Sealed | Non-fatal skip for unseal-only checks | Structured checks exit 0 |
| QS-11 | compatibility | MCP host lists tools | stdio MCP | vault_* tools + prompts registered | Adapter registration tests |
| QS-12 | reliability | Companion socket connect under load | Agent under launchd | Connect success per SLO | companion-socket-connect-rate |
| QS-13 | functional-suitability | Operator put + list secret | Unsealed, bound namespace | Secret listed with public metadata only | BDD put_secret + list_secrets features |
| QS-14 | safety | Spawn proxy called | Any unsealed session | Always deny until capability enabled | spawn_command always PolicyDenied |
