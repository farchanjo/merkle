//! Common re-exports for driving adapters.
//!
//! Import `merkle_application::prelude::*` to get the most frequently
//! used command/query handler types without verbose `use` paths.

pub use crate::{AppContext, AppError};

// Commands — full implementations.
pub use crate::commands::{
    bind_namespace::{BindNamespaceCommand, BindNamespaceOutput},
    describe_secret::{DescribeSecretCommand, DescribeSecretOutput},
    init_vault::{InitVaultCommand, InitVaultOutput},
    list_devices::{ListDevicesCommand, ListDevicesOutput},
    list_secrets::{ListSecretsCommand, ListSecretsOutput},
    pair_device::{PairDeviceCommand, PairDeviceOutput},
    put_secret::{PutSecretCommand, PutSecretOutput},
    reveal_secret::{RevealSecretCommand, RevealSecretOutput},
    rollback_secret::{RollbackSecretCommand, RollbackSecretOutput},
    rotate_secret::{RotateSecretCommand, RotateSecretOutput},
    seal_vault::{SealVaultCommand, SealVaultOutput},
    trigger_backup::{TriggerBackupCommand, TriggerBackupOutput},
    unseal_vault::{UnsealVaultCommand, UnsealVaultOutput},
};

// Commands — scaffolded.
pub use crate::commands::{
    crypto_decrypt::{CryptoDecryptCommand, CryptoDecryptOutput},
    crypto_sign::{CryptoSignCommand, CryptoSignOutput},
    delete_secret::{DeleteSecretCommand, DeleteSecretOutput},
    execute_restore::{ExecuteRestoreCommand, ExecuteRestoreOutput},
    http_download::{HttpDownloadCommand, HttpDownloadOutput},
    http_request::{HttpRequestCommand, HttpRequestOutput},
    http_upload::{HttpUploadCommand, HttpUploadOutput},
    port_forward::{PortForwardCommand, PortForwardOutput},
    restore_plan::{RestorePlanCommand, RestorePlanOutput},
    revoke_device::{RevokeDeviceCommand, RevokeDeviceOutput},
    revoke_tempfile::{RevokeTempfileCommand, RevokeTempfileOutput},
    search_secrets::{SearchSecretsCommand, SearchSecretsOutput},
    spawn_command::{SpawnCommandCommand, SpawnCommandOutput},
    ssh_copy::{SshCopyCommand, SshCopyOutput},
    ssh_exec::SshExecCommand,
    ssh_shell::{SshShellCommand, SshShellOutput},
    use_token::{UseTokenCommand, UseTokenOutput},
    verify_recovery_key::{VerifyRecoveryKeyCommand, VerifyRecoveryKeyOutput},
    write_fifo::{WriteFifoCommand, WriteFifoOutput},
    write_tempfile::{WriteTempfileCommand, WriteTempfileOutput},
};

// Queries — full implementations.
pub use crate::queries::{
    agent_status::{AgentStatusOutput, AgentStatusQuery},
    list_backups::{ListBackupsOutput, ListBackupsQuery},
    list_namespaces::{ListNamespacesOutput, ListNamespacesQuery},
    query_audit::{QueryAuditOutput, QueryAuditQuery},
    verify_chain::{VerifyChainOutput, VerifyChainQuery},
};

// Queries — scaffolded.
pub use crate::queries::doctor::{DoctorOutput, DoctorQuery};
