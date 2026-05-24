# Bounded Context Map

This document declares the strategic DDD relationship types for the 7 cross-context
edges in Merkle Vault. Each edge carries: relationship type, upstream/downstream
direction, and the party that owns the contract.

Relationship type legend:

- **C/S** Customer-Supplier: upstream produces; downstream consumes; upstream owns the contract.
- **CF** Conformist: downstream adopts upstream model verbatim; no translation layer.
- **ACL** Anti-Corruption Layer: downstream translates; ACL owned by downstream.
- **SK** Shared Kernel: both contexts co-own a shared subset of the model; changes require joint agreement.
- **P** Partnership: both contexts evolve together; neither is purely upstream or downstream.

## Edge table

| # | Edge | Direction | Relationship | Contract owner | Notes |
|---|------|-----------|--------------|----------------|-------|
| 1 | Identity and Sealing → Secret Storage | unwraps Namespace DEKs | **C/S** | Identity and Sealing (upstream) | SecretStorage conforms to the DEK envelope format; no translation needed — **Conformist** on the DEK shape. |
| 2 | Secret Storage → Access Mediation | resolved-by (provides Private Blob) | **C/S** | Secret Storage (upstream) | Access Mediation calls into Secret Storage to resolve a Handle to a Private Blob. Secret Storage owns the Handle and Blob contract. |
| 3 | Access Mediation → Audit and Compliance | emits Audit Entry on every operation | **C/S** | Audit and Compliance (upstream) | Access Mediation is the primary Audit Entry producer. AuditCompliance owns the #AuditEntry schema; AccessMediation conforms. |
| 4 | Secret Storage → Backup and Recovery | snapshotted-by (provides vault state) | **C/S** | Secret Storage (upstream) | BackupRecovery reads vault state from SecretStorage. SecretStorage owns the export contract; BackupRecovery is a Conformist consumer. |
| 5 | Policy and Permissions → Access Mediation | governs Proxy Tool execution and Reveal decisions | **C/S** | Policy and Permissions (upstream) | AccessMediation calls PolicyPermissions for every policy evaluation. PolicyPermissions owns the RevealPolicy and RateLimit contracts. |
| 6 | Policy and Permissions → Secret Storage | governs Namespace Policy and retention | **C/S** | Policy and Permissions (upstream) | SecretStorage delegates retention and namespace-policy lookups to PolicyPermissions. PolicyPermissions owns the NamespacePolicy contract. |
| 7 | Audit and Compliance → Access Mediation | chains audit entries for all mediated access | **CF** | Audit and Compliance (upstream) | **Direction correction**: the README mermaid arrow `AuditCompliance →|chains all| AccessMediation` is misleading. The actual data flow is AccessMediation → AuditCompliance (edge 3 above). This edge represents AuditCompliance reading back chained entries that originated from Access Mediation in order to verify chain continuity. The dependency for chain validation is read-only and directed AuditCompliance → AuditCompliance internal. No separate cross-context dependency on AccessMediation is created; the README arrow should be read as "AuditCompliance validates all entries emitted by AccessMediation" — not a runtime call from AuditCompliance into AccessMediation. **No code-level import from audit_compliance into access_mediation is correct.** |

## Shared Kernel declaration

| Shared artifact | Contexts | Owner | Notes |
|-----------------|----------|-------|-------|
| `#HmacSignature` (`audit_compliance.#HmacSignature`) | Audit and Compliance, Backup and Recovery | Audit and Compliance | Declared in `schemas/audit_compliance/hmac_signature.cue`. BackupRecovery imports it via `import "fapp.dev/merkle/schemas/audit_compliance"` in `backup_recovery/backup.cue`. Changes to the HMAC signature shape require joint agreement between both contexts. |

## Notes on direction correction (edge 7)

The workspace.dsl line:

```
merkleVault.vaultAgent.auditComplianceDomain -> merkleVault.vaultAgent.accessMediationDomain "Chains Audit Entries for all mediated access via" "In-process Rust trait call"
```

is incorrectly directed. AuditCompliance does not call into AccessMediation at runtime.
The correct dependency is AccessMediation → AuditCompliance (edge 3). The DSL relationship
should be reversed or removed in a future ADR. This context map documents the correction;
the workspace.dsl is not modified here per the Wave-1 scope constraint.
