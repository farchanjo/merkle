//! Clap command-line interface definitions.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::output::OutputFormat;

/// Merkle operator CLI — manages secrets in the Vault Agent.
///
/// All subcommands communicate with the Vault Agent over the Companion Socket
/// (Unix domain socket). Run `merkle <subcommand> --help` for details.
#[derive(Debug, Parser)]
#[command(
    name = "merkle",
    version,
    about = "Merkle operator CLI — manages secrets in the Vault Agent",
    long_about = None,
)]
pub struct Cli {
    /// Path to the Companion Socket (overrides config).
    #[arg(long, env = "MERKLE_SOCKET", global = true, value_name = "PATH")]
    pub socket: Option<PathBuf>,

    /// Output format.
    #[arg(
        long,
        short = 'o',
        global = true,
        default_value = "human",
        value_name = "FORMAT"
    )]
    pub output: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

// ---------------------------------------------------------------------------
// Top-level subcommands
// ---------------------------------------------------------------------------

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// First-run interactive bootstrap wizard.
    Init(InitArgs),

    /// Unseal the Vault Agent (load the Vault Root Key into protected memory).
    Unseal(UnsealArgs),

    /// Seal the Vault Agent (zeroize the Vault Root Key).
    Seal,

    /// Show agent health and seal state.
    Status,

    /// Bind a Namespace to the current session (one-shot).
    Bind(BindArgs),

    /// Create or overwrite a Secret (reads payload from stdin).
    Put(PutArgs),

    /// List Secrets in a Namespace.
    List(ListArgs),

    /// Obtain a Use Token for a low/medium-sensitivity Secret.
    Get(GetArgs),

    /// Show read-only public metadata for a Secret.
    Describe(DescribeArgs),

    /// Reveal the plaintext of a Secret (interactive OOB if needed).
    Reveal(RevealArgs),

    /// Rotate the active value of a Secret (reads new payload from stdin).
    Rotate(RotateArgs),

    /// Permanently delete a Secret and all its versions.
    Delete(DeleteArgs),

    /// Full-text search within a Namespace.
    Search(SearchArgs),

    /// Query the append-only audit log.
    Audit(AuditArgs),

    /// Trigger or list backups.
    Backup(BackupArgs),

    /// Create or execute a restore plan.
    Restore(RestoreArgs),

    /// Manage Companion Devices (pair / list / revoke).
    Device(DeviceArgs),

    /// Verify that the stored Recovery Key matches `config.toml`.
    VerifyRecoveryKey(VerifyRecoveryKeyArgs),

    /// Run self-diagnostics on the Vault Agent.
    Doctor(DoctorArgs),
}

// ---------------------------------------------------------------------------
// Per-subcommand argument structs
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct InitArgs {
    /// Run non-interactively with default values (CI mode).
    #[arg(long)]
    pub non_interactive: bool,
}

#[derive(Debug, Parser)]
pub struct UnsealArgs {
    /// Read the passphrase from the TTY instead of the OS Keychain.
    #[arg(long)]
    pub passphrase: bool,
}

#[derive(Debug, Parser)]
pub struct BindArgs {
    /// Namespace label to bind (creates the namespace if absent).
    pub namespace_label: String,
}

#[derive(Debug, Parser)]
pub struct PutArgs {
    /// Secret handle: `vault://<ns>/<category>/<name>` or `<ns>/<cat>/<name>`.
    pub handle: String,

    /// Sensitivity level.
    #[arg(long, default_value = "medium")]
    pub sensitivity: String,

    /// Tags in `key:value` form (repeatable).
    #[arg(long = "tag", value_name = "KEY:VALUE")]
    pub tags: Vec<String>,

    /// Secret category (ssh, password, token, …).
    #[arg(long, default_value = "note")]
    pub category: String,

    /// Human-readable description.
    #[arg(long)]
    pub description: Option<String>,

    /// Force overwrite if a Secret with the same name exists.
    #[arg(long)]
    pub force: bool,

    /// Treat the stdin payload as Base64-encoded binary (not UTF-8 text).
    ///
    /// Use for SSH private keys, TLS certificates, JWK blobs, or any binary
    /// secret. The agent will base64-decode the value before encrypting.
    #[arg(long)]
    pub base64: bool,
}

#[derive(Debug, Parser)]
pub struct ListArgs {
    /// Namespace label (omit to list all namespaces).
    pub namespace: Option<String>,

    /// FTS5 filter expression.
    #[arg(long)]
    pub filter: Option<String>,

    /// Filter by category.
    #[arg(long)]
    pub category: Option<String>,

    /// Filter by sensitivity.
    #[arg(long)]
    pub sensitivity: Option<String>,

    /// Maximum number of results.
    #[arg(long, default_value = "50")]
    pub limit: u32,
}

#[derive(Debug, Parser)]
pub struct GetArgs {
    /// Secret handle.
    pub handle: String,

    /// Justification recorded in the audit log.
    #[arg(long)]
    pub reason: Option<String>,
}

#[derive(Debug, Parser)]
pub struct DescribeArgs {
    /// Secret handle.
    pub handle: String,
}

#[derive(Debug, Parser)]
pub struct RevealArgs {
    /// Secret handle.
    pub handle: String,

    /// Justification for the reveal (mandatory).
    #[arg(long)]
    pub reason: String,
}

#[derive(Debug, Parser)]
pub struct RotateArgs {
    /// Secret handle.
    pub handle: String,

    /// Human-readable purpose recorded in the audit log.
    #[arg(long, default_value = "manual rotation")]
    pub purpose: String,

    /// Treat the new stdin payload as Base64-encoded binary (not UTF-8 text).
    #[arg(long)]
    pub base64: bool,
}

#[derive(Debug, Parser)]
pub struct DeleteArgs {
    /// Secret handle.
    pub handle: String,

    /// Confirm destructive deletion (required).
    #[arg(long)]
    pub confirm: bool,
}

#[derive(Debug, Parser)]
pub struct SearchArgs {
    /// Namespace label.
    pub namespace: String,

    /// FTS5 query expression.
    pub query: String,

    /// Maximum number of results.
    #[arg(long, default_value = "20")]
    pub limit: u32,
}

#[derive(Debug, Parser)]
pub struct AuditArgs {
    /// Administrative audit action. Omit to query the log (default).
    #[command(subcommand)]
    pub action: Option<AuditAction>,

    /// Filter by operation type.
    #[arg(long)]
    pub op: Option<String>,

    /// Filter entries at or after this ISO 8601 timestamp.
    #[arg(long)]
    pub since: Option<String>,

    /// Maximum number of entries.
    #[arg(long, default_value = "50")]
    pub limit: u32,
}

#[derive(Debug, Subcommand)]
pub enum AuditAction {
    /// Pin a trusted audit baseline to recover a verifiable chain (ADR-0029).
    ///
    /// Use after a key-provenance incident where `doctor` reports the audit
    /// chain unhealthy (`HmacMismatch`) but the hash chain is intact. Appends a
    /// `rebaseline` marker and anchors verification to it; the operator-attested
    /// prefix is quarantined. Back up the vault first.
    Rebaseline(AuditRebaselineArgs),
}

#[derive(Debug, Parser)]
pub struct AuditRebaselineArgs {
    /// Justification recorded with the pinned baseline.
    #[arg(long)]
    pub reason: String,

    /// Confirm this integrity-affecting operation (required).
    #[arg(long)]
    pub confirm: bool,
}

#[derive(Debug, Parser)]
pub struct BackupArgs {
    #[command(subcommand)]
    pub action: BackupAction,
}

#[derive(Debug, Subcommand)]
pub enum BackupAction {
    /// Trigger an on-demand backup immediately.
    Now(BackupNowArgs),
    /// List available backup snapshots.
    List(BackupListArgs),
}

#[derive(Debug, Parser)]
pub struct BackupNowArgs {
    /// Free-form note appended to the audit entry.
    #[arg(long)]
    pub note: Option<String>,
}

#[derive(Debug, Parser)]
pub struct BackupListArgs {
    /// Namespace label (informational, not a filter in the current API).
    pub namespace: Option<String>,

    /// Maximum number of snapshots.
    #[arg(long, default_value = "20")]
    pub limit: u32,
}

#[derive(Debug, Parser)]
pub struct RestoreArgs {
    #[command(subcommand)]
    pub action: RestoreAction,
}

#[derive(Debug, Subcommand)]
pub enum RestoreAction {
    /// Create a restore plan from a backup snapshot (preview only).
    Plan(RestorePlanArgs),
    /// Execute a previously created restore plan.
    Execute(RestoreExecuteArgs),
}

#[derive(Debug, Parser)]
pub struct RestorePlanArgs {
    /// Backup snapshot filename (not full path).
    pub backup_id: String,

    /// Conflict resolution mode.
    #[arg(long, default_value = "newest_wins")]
    pub mode: String,
}

#[derive(Debug, Parser)]
pub struct RestoreExecuteArgs {
    /// Plan ID returned by `restore plan`.
    pub plan_id: String,
}

#[derive(Debug, Parser)]
pub struct DeviceArgs {
    #[command(subcommand)]
    pub action: DeviceAction,
}

#[derive(Debug, Subcommand)]
pub enum DeviceAction {
    /// Pair a new Companion Device.
    Pair(DevicePairArgs),
    /// List enrolled Companion Devices.
    List,
    /// Revoke a Companion Device by ID.
    Revoke(DeviceRevokeArgs),
}

#[derive(Debug, Parser)]
pub struct DevicePairArgs {
    /// Human-readable device name.
    #[arg(long)]
    pub name: String,

    /// Device class: `hw`, `enclave`, or `software`.
    #[arg(long)]
    pub class: String,
}

#[derive(Debug, Parser)]
pub struct DeviceRevokeArgs {
    /// Device ID to revoke.
    pub device_id: String,
}

#[derive(Debug, Parser)]
pub struct VerifyRecoveryKeyArgs {
    /// Path to an identity file instead of reading from TTY.
    #[arg(long, value_name = "PATH")]
    pub identity_file: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct DoctorArgs {
    /// Check durability (WAL, FTS5, disk space).
    #[arg(long)]
    pub durability: bool,

    /// Verify the audit chain hash integrity.
    #[arg(long)]
    pub chain: bool,

    /// Run all checks.
    #[arg(long)]
    pub all: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status() {
        let cli = Cli::try_parse_from(["merkle", "status"]).expect("parse status");
        assert!(matches!(cli.command, Commands::Status));
    }

    #[test]
    fn parse_unseal_passphrase() {
        let cli = Cli::try_parse_from(["merkle", "unseal", "--passphrase"])
            .expect("parse unseal --passphrase");
        let Commands::Unseal(args) = cli.command else {
            panic!("expected Unseal");
        };
        assert!(args.passphrase);
    }

    #[test]
    fn parse_put_with_tags() {
        let cli = Cli::try_parse_from([
            "merkle",
            "put",
            "vault://ns/password/example",
            "--sensitivity",
            "high",
            "--tag",
            "env:prod",
            "--tag",
            "role:bastion",
        ])
        .expect("parse put");
        let Commands::Put(args) = cli.command else {
            panic!("expected Put");
        };
        assert_eq!(args.sensitivity, "high");
        assert_eq!(args.tags, ["env:prod", "role:bastion"]);
    }

    #[test]
    fn parse_delete_requires_no_implicit_confirm() {
        let cli = Cli::try_parse_from(["merkle", "delete", "vault://ns/password/example"])
            .expect("parse delete without --confirm");
        let Commands::Delete(args) = cli.command else {
            panic!("expected Delete");
        };
        assert!(!args.confirm, "confirm should default to false");
    }

    #[test]
    fn parse_backup_now() {
        let cli = Cli::try_parse_from(["merkle", "backup", "now"]).expect("parse backup now");
        let Commands::Backup(b) = cli.command else {
            panic!("expected Backup");
        };
        assert!(matches!(b.action, BackupAction::Now(_)));
    }

    #[test]
    fn parse_restore_plan() {
        let cli = Cli::try_parse_from([
            "merkle",
            "restore",
            "plan",
            "merkle-bk-2026.merkle.age",
            "--mode",
            "merge",
        ])
        .expect("parse restore plan");
        let Commands::Restore(r) = cli.command else {
            panic!("expected Restore");
        };
        let RestoreAction::Plan(args) = r.action else {
            panic!("expected Plan");
        };
        assert_eq!(args.mode, "merge");
    }

    #[test]
    fn parse_device_pair() {
        let cli = Cli::try_parse_from([
            "merkle",
            "device",
            "pair",
            "--name",
            "yubikey-5",
            "--class",
            "hw",
        ])
        .expect("parse device pair");
        let Commands::Device(d) = cli.command else {
            panic!("expected Device");
        };
        let DeviceAction::Pair(args) = d.action else {
            panic!("expected Pair");
        };
        assert_eq!(args.class, "hw");
    }

    #[test]
    fn parse_output_json() {
        let cli =
            Cli::try_parse_from(["merkle", "--output", "json", "status"]).expect("parse output");
        assert_eq!(cli.output, OutputFormat::Json);
    }

    #[test]
    fn parse_doctor_all() {
        let cli = Cli::try_parse_from(["merkle", "doctor", "--all"]).expect("parse doctor --all");
        let Commands::Doctor(args) = cli.command else {
            panic!("expected Doctor");
        };
        assert!(args.all);
    }

    #[test]
    fn parse_audit_rebaseline() {
        let cli = Cli::try_parse_from([
            "merkle",
            "audit",
            "rebaseline",
            "--reason",
            "recovery: quarantine pre-rotation prefix",
            "--confirm",
        ])
        .expect("parse audit rebaseline");
        let Commands::Audit(a) = cli.command else {
            panic!("expected Audit");
        };
        let Some(AuditAction::Rebaseline(rb)) = a.action else {
            panic!("expected Rebaseline action");
        };
        assert_eq!(rb.reason, "recovery: quarantine pre-rotation prefix");
        assert!(rb.confirm);
    }

    #[test]
    fn parse_audit_query_has_no_action() {
        let cli = Cli::try_parse_from(["merkle", "audit", "--op", "put", "--limit", "10"])
            .expect("parse audit query");
        let Commands::Audit(a) = cli.command else {
            panic!("expected Audit");
        };
        assert!(
            a.action.is_none(),
            "a bare audit query must carry no subcommand action"
        );
        assert_eq!(a.op.as_deref(), Some("put"));
    }
}
