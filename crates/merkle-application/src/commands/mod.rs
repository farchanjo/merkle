//! Command handlers — write-side of the CQRS split.
//!
//! Each sub-module owns one use-case struct and its `execute` method.
//! Commands mutate state through driven port traits; they never reach into
//! adapter crates.

pub mod bind_namespace;
pub mod crypto_decrypt;
pub mod crypto_sign;
pub mod delete_secret;
pub mod describe_secret;
pub mod disaster_recover;
pub mod execute_restore;
pub mod http_download;
pub mod http_request;
pub mod http_upload;
pub mod init_vault;
pub mod list_devices;
pub mod list_secrets;
pub mod pair_device;
pub mod port_forward;
pub mod put_secret;
pub mod restore_plan;
pub mod reveal_secret;
pub mod revoke_device;
pub mod revoke_tempfile;
pub mod rollback_secret;
pub mod rotate_secret;
pub mod seal_vault;
pub mod search_secrets;
pub mod set_audit_baseline;
pub mod spawn_command;
pub mod ssh_copy;
pub mod ssh_exec;
pub mod ssh_shell;
pub mod trigger_backup;
pub mod unseal_vault;
pub mod use_token;
pub mod verify_recovery_key;
pub mod write_fifo;
pub mod write_tempfile;
