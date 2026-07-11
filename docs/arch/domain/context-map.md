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

## Schema catalog

Full CUE contracts: [schemas/README.md](../schemas/README.md).

### Schema files

- [`schemas/access_mediation/access_mediation_identity_vo.cue`](../schemas/access_mediation/access_mediation_identity_vo.cue)
- [`schemas/access_mediation/access_mediation_primitives_0.cue`](../schemas/access_mediation/access_mediation_primitives_0.cue)
- [`schemas/access_mediation/access_mediation_primitives_1.cue`](../schemas/access_mediation/access_mediation_primitives_1.cue)
- [`schemas/access_mediation/access_mediation_primitives_2.cue`](../schemas/access_mediation/access_mediation_primitives_2.cue)
- [`schemas/access_mediation/access_mediation_primitives_3.cue`](../schemas/access_mediation/access_mediation_primitives_3.cue)
- [`schemas/access_mediation/access_mediation_primitives_4.cue`](../schemas/access_mediation/access_mediation_primitives_4.cue)
- [`schemas/access_mediation/companion_socket_session.cue`](../schemas/access_mediation/companion_socket_session.cue)
- [`schemas/access_mediation/companion_socket_session_companionsocketsessionpart1.cue`](../schemas/access_mediation/companion_socket_session_companionsocketsessionpart1.cue)
- [`schemas/access_mediation/fifo.cue`](../schemas/access_mediation/fifo.cue)
- [`schemas/access_mediation/oob_resolution.cue`](../schemas/access_mediation/oob_resolution.cue)
- [`schemas/access_mediation/operator_confirmation.cue`](../schemas/access_mediation/operator_confirmation.cue)
- [`schemas/access_mediation/proxy_executor.cue`](../schemas/access_mediation/proxy_executor.cue)
- [`schemas/access_mediation/proxy_httpdownloadinput.cue`](../schemas/access_mediation/proxy_httpdownloadinput.cue)
- [`schemas/access_mediation/proxy_httpdownloadoutput.cue`](../schemas/access_mediation/proxy_httpdownloadoutput.cue)
- [`schemas/access_mediation/proxy_httprequestinput.cue`](../schemas/access_mediation/proxy_httprequestinput.cue)
- [`schemas/access_mediation/proxy_httprequestoutput.cue`](../schemas/access_mediation/proxy_httprequestoutput.cue)
- [`schemas/access_mediation/proxy_httpuploadinput.cue`](../schemas/access_mediation/proxy_httpuploadinput.cue)
- [`schemas/access_mediation/proxy_httpuploadoutput.cue`](../schemas/access_mediation/proxy_httpuploadoutput.cue)
- [`schemas/access_mediation/proxy_spawninput.cue`](../schemas/access_mediation/proxy_spawninput.cue)
- [`schemas/access_mediation/proxy_spawnoutput.cue`](../schemas/access_mediation/proxy_spawnoutput.cue)
- [`schemas/access_mediation/proxy_sshcopyinput.cue`](../schemas/access_mediation/proxy_sshcopyinput.cue)
- [`schemas/access_mediation/proxy_sshcopyoutput.cue`](../schemas/access_mediation/proxy_sshcopyoutput.cue)
- [`schemas/access_mediation/proxy_sshexecinput.cue`](../schemas/access_mediation/proxy_sshexecinput.cue)
- [`schemas/access_mediation/proxy_sshexecoutput.cue`](../schemas/access_mediation/proxy_sshexecoutput.cue)
- [`schemas/access_mediation/proxy_sshportforwardinput.cue`](../schemas/access_mediation/proxy_sshportforwardinput.cue)
- [`schemas/access_mediation/proxy_sshportforwardoutput.cue`](../schemas/access_mediation/proxy_sshportforwardoutput.cue)
- [`schemas/access_mediation/proxy_sshshellinput.cue`](../schemas/access_mediation/proxy_sshshellinput.cue)
- [`schemas/access_mediation/proxy_sshshelloutput.cue`](../schemas/access_mediation/proxy_sshshelloutput.cue)
- [`schemas/access_mediation/proxy_writetempfileinput.cue`](../schemas/access_mediation/proxy_writetempfileinput.cue)
- [`schemas/access_mediation/proxy_writetempfileoutput.cue`](../schemas/access_mediation/proxy_writetempfileoutput.cue)
- [`schemas/access_mediation/reveal_request.cue`](../schemas/access_mediation/reveal_request.cue)
- [`schemas/access_mediation/reveal_request_revealrequestpart1.cue`](../schemas/access_mediation/reveal_request_revealrequestpart1.cue)
- [`schemas/access_mediation/tempfile.cue`](../schemas/access_mediation/tempfile.cue)
- [`schemas/access_mediation/tempfile_tempfilepart1.cue`](../schemas/access_mediation/tempfile_tempfilepart1.cue)
- [`schemas/access_mediation/use_token.cue`](../schemas/access_mediation/use_token.cue)
- [`schemas/access_mediation/use_token_usetokenpart1.cue`](../schemas/access_mediation/use_token_usetokenpart1.cue)
- [`schemas/audit_compliance/audit_compliance_identity_vo.cue`](../schemas/audit_compliance/audit_compliance_identity_vo.cue)
- [`schemas/audit_compliance/audit_compliance_primitives_0.cue`](../schemas/audit_compliance/audit_compliance_primitives_0.cue)
- [`schemas/audit_compliance/audit_compliance_primitives_1.cue`](../schemas/audit_compliance/audit_compliance_primitives_1.cue)
- [`schemas/audit_compliance/audit_compliance_primitives_2.cue`](../schemas/audit_compliance/audit_compliance_primitives_2.cue)
- [`schemas/audit_compliance/audit_entry.cue`](../schemas/audit_compliance/audit_entry.cue)
- [`schemas/audit_compliance/audit_entry_auditentrypart1.cue`](../schemas/audit_compliance/audit_entry_auditentrypart1.cue)
- [`schemas/audit_compliance/audit_entry_auditentrypart2.cue`](../schemas/audit_compliance/audit_entry_auditentrypart2.cue)
- [`schemas/audit_compliance/audit_query.cue`](../schemas/audit_compliance/audit_query.cue)
- [`schemas/audit_compliance/audit_query_auditquerypart1.cue`](../schemas/audit_compliance/audit_query_auditquerypart1.cue)
- [`schemas/audit_compliance/audit_value_objects.cue`](../schemas/audit_compliance/audit_value_objects.cue)
- [`schemas/audit_compliance/chain_verifier.cue`](../schemas/audit_compliance/chain_verifier.cue)
- [`schemas/audit_compliance/chain_verifier_verifyresultpart1.cue`](../schemas/audit_compliance/chain_verifier_verifyresultpart1.cue)
- [`schemas/audit_compliance/hmac_signature.cue`](../schemas/audit_compliance/hmac_signature.cue)
- [`schemas/backup_recovery/anacron_state.cue`](../schemas/backup_recovery/anacron_state.cue)
- [`schemas/backup_recovery/backup.cue`](../schemas/backup_recovery/backup.cue)
- [`schemas/backup_recovery/backup_backuppart1.cue`](../schemas/backup_recovery/backup_backuppart1.cue)
- [`schemas/backup_recovery/backup_recovery_identity_vo.cue`](../schemas/backup_recovery/backup_recovery_identity_vo.cue)
- [`schemas/backup_recovery/backup_recovery_primitives_0.cue`](../schemas/backup_recovery/backup_recovery_primitives_0.cue)
- [`schemas/backup_recovery/backup_recovery_primitives_1.cue`](../schemas/backup_recovery/backup_recovery_primitives_1.cue)
- [`schemas/backup_recovery/backup_recovery_primitives_2.cue`](../schemas/backup_recovery/backup_recovery_primitives_2.cue)
- [`schemas/backup_recovery/backup_scheduler.cue`](../schemas/backup_recovery/backup_scheduler.cue)
- [`schemas/backup_recovery/backup_scheduler_backupschedulerpart1.cue`](../schemas/backup_recovery/backup_scheduler_backupschedulerpart1.cue)
- [`schemas/backup_recovery/restore_plan.cue`](../schemas/backup_recovery/restore_plan.cue)
- [`schemas/backup_recovery/restore_plan_restoreplanpart1.cue`](../schemas/backup_recovery/restore_plan_restoreplanpart1.cue)
- [`schemas/identity_and_sealing/identity_and_sealing_identity_vo.cue`](../schemas/identity_and_sealing/identity_and_sealing_identity_vo.cue)
- [`schemas/identity_and_sealing/identity_and_sealing_primitives_0.cue`](../schemas/identity_and_sealing/identity_and_sealing_primitives_0.cue)
- [`schemas/identity_and_sealing/identity_and_sealing_primitives_1.cue`](../schemas/identity_and_sealing/identity_and_sealing_primitives_1.cue)
- [`schemas/identity_and_sealing/init_vault.cue`](../schemas/identity_and_sealing/init_vault.cue)
- [`schemas/identity_and_sealing/keystore_config.cue`](../schemas/identity_and_sealing/keystore_config.cue)
- [`schemas/identity_and_sealing/master_key.cue`](../schemas/identity_and_sealing/master_key.cue)
- [`schemas/identity_and_sealing/master_key_ref.cue`](../schemas/identity_and_sealing/master_key_ref.cue)
- [`schemas/identity_and_sealing/namespace_dek.cue`](../schemas/identity_and_sealing/namespace_dek.cue)
- [`schemas/identity_and_sealing/recovery_key.cue`](../schemas/identity_and_sealing/recovery_key.cue)
- [`schemas/identity_and_sealing/sealed_state.cue`](../schemas/identity_and_sealing/sealed_state.cue)
- [`schemas/identity_and_sealing/unseal_preconditions.cue`](../schemas/identity_and_sealing/unseal_preconditions.cue)
- [`schemas/identity_and_sealing/vault_identity.cue`](../schemas/identity_and_sealing/vault_identity.cue)
- [`schemas/identity_and_sealing/vault_identity_vaultidentitypart1.cue`](../schemas/identity_and_sealing/vault_identity_vaultidentitypart1.cue)
- [`schemas/identity_and_sealing/vault_root_key.cue`](../schemas/identity_and_sealing/vault_root_key.cue)
- [`schemas/policy_permissions/allowed_consumers.cue`](../schemas/policy_permissions/allowed_consumers.cue)
- [`schemas/policy_permissions/namespace_policy.cue`](../schemas/policy_permissions/namespace_policy.cue)
- [`schemas/policy_permissions/namespace_policy_namespacepolicypart1.cue`](../schemas/policy_permissions/namespace_policy_namespacepolicypart1.cue)
- [`schemas/policy_permissions/namespace_policy_namespacepolicypart2.cue`](../schemas/policy_permissions/namespace_policy_namespacepolicypart2.cue)
- [`schemas/policy_permissions/namespace_policy_vos.cue`](../schemas/policy_permissions/namespace_policy_vos.cue)
- [`schemas/policy_permissions/policy_permissions_primitives_0.cue`](../schemas/policy_permissions/policy_permissions_primitives_0.cue)
- [`schemas/policy_permissions/policy_permissions_primitives_1.cue`](../schemas/policy_permissions/policy_permissions_primitives_1.cue)
- [`schemas/policy_permissions/rate_limit.cue`](../schemas/policy_permissions/rate_limit.cue)
- [`schemas/policy_permissions/reveal_policy.cue`](../schemas/policy_permissions/reveal_policy.cue)
- [`schemas/policy_permissions/security_profile.cue`](../schemas/policy_permissions/security_profile.cue)
- [`schemas/policy_permissions/sensitivity_alias.cue`](../schemas/policy_permissions/sensitivity_alias.cue)
- [`schemas/secret_storage/categories/cert/cert.cue`](../schemas/secret_storage/categories/cert/cert.cue)
- [`schemas/secret_storage/categories/cert/cert_publicmetapart1.cue`](../schemas/secret_storage/categories/cert/cert_publicmetapart1.cue)
- [`schemas/secret_storage/categories/cloud/cloud.cue`](../schemas/secret_storage/categories/cloud/cloud.cue)
- [`schemas/secret_storage/categories/database/database.cue`](../schemas/secret_storage/categories/database/database.cue)
- [`schemas/secret_storage/categories/database/database_publicmetapart1.cue`](../schemas/secret_storage/categories/database/database_publicmetapart1.cue)
- [`schemas/secret_storage/categories/env/env.cue`](../schemas/secret_storage/categories/env/env.cue)
- [`schemas/secret_storage/categories/gpg/gpg.cue`](../schemas/secret_storage/categories/gpg/gpg.cue)
- [`schemas/secret_storage/categories/key/key.cue`](../schemas/secret_storage/categories/key/key.cue)
- [`schemas/secret_storage/categories/note/note.cue`](../schemas/secret_storage/categories/note/note.cue)
- [`schemas/secret_storage/categories/otp/otp.cue`](../schemas/secret_storage/categories/otp/otp.cue)
- [`schemas/secret_storage/categories/password/password.cue`](../schemas/secret_storage/categories/password/password.cue)
- [`schemas/secret_storage/categories/ssh/ssh.cue`](../schemas/secret_storage/categories/ssh/ssh.cue)
- [`schemas/secret_storage/categories/ssh/ssh_publicmetapart1.cue`](../schemas/secret_storage/categories/ssh/ssh_publicmetapart1.cue)
- [`schemas/secret_storage/categories/token/token.cue`](../schemas/secret_storage/categories/token/token.cue)
- [`schemas/secret_storage/category.cue`](../schemas/secret_storage/category.cue)
- [`schemas/secret_storage/handle.cue`](../schemas/secret_storage/handle.cue)
- [`schemas/secret_storage/namespace.cue`](../schemas/secret_storage/namespace.cue)
- [`schemas/secret_storage/namespace_id.cue`](../schemas/secret_storage/namespace_id.cue)
- [`schemas/secret_storage/private_blob.cue`](../schemas/secret_storage/private_blob.cue)
- [`schemas/secret_storage/public_metadata.cue`](../schemas/secret_storage/public_metadata.cue)
- [`schemas/secret_storage/secret.cue`](../schemas/secret_storage/secret.cue)
- [`schemas/secret_storage/secret_id.cue`](../schemas/secret_storage/secret_id.cue)
- [`schemas/secret_storage/secret_secretpart1.cue`](../schemas/secret_storage/secret_secretpart1.cue)
- [`schemas/secret_storage/secret_secretpart2.cue`](../schemas/secret_storage/secret_secretpart2.cue)
- [`schemas/secret_storage/secret_storage_identity_vo.cue`](../schemas/secret_storage/secret_storage_identity_vo.cue)
- [`schemas/secret_storage/secret_storage_primitives_0.cue`](../schemas/secret_storage/secret_storage_primitives_0.cue)
- [`schemas/secret_storage/secret_storage_primitives_1.cue`](../schemas/secret_storage/secret_storage_primitives_1.cue)
- [`schemas/secret_storage/secret_storage_primitives_2.cue`](../schemas/secret_storage/secret_storage_primitives_2.cue)
- [`schemas/secret_storage/secret_storage_primitives_3.cue`](../schemas/secret_storage/secret_storage_primitives_3.cue)
- [`schemas/secret_storage/secret_storage_primitives_4.cue`](../schemas/secret_storage/secret_storage_primitives_4.cue)
- [`schemas/secret_storage/secret_storage_primitives_5.cue`](../schemas/secret_storage/secret_storage_primitives_5.cue)
- [`schemas/secret_storage/secret_storage_primitives_6.cue`](../schemas/secret_storage/secret_storage_primitives_6.cue)
- [`schemas/secret_storage/secret_storage_primitives_7.cue`](../schemas/secret_storage/secret_storage_primitives_7.cue)
- [`schemas/secret_storage/secret_storage_primitives_8.cue`](../schemas/secret_storage/secret_storage_primitives_8.cue)
- [`schemas/secret_storage/secret_version.cue`](../schemas/secret_storage/secret_version.cue)
- [`schemas/secret_storage/sensitivity.cue`](../schemas/secret_storage/sensitivity.cue)
- [`schemas/secret_storage/tag.cue`](../schemas/secret_storage/tag.cue)
