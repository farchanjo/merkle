//! # merkle-domain-backup-recovery
//!
//! **Backup and Recovery** bounded context.
//!
//! Implements the domain core for scheduled encrypted vault exports and safe,
//! previewed restore operations.  See
//! `docs/arch/domain/backup-recovery.md` and
//! `docs/arch/schemas/backup_recovery/` for the canonical narrative and
//! CUE type shapes.
//!
//! ## Aggregates
//!
//! - [`backup::Backup`] (AggregateRoot) — completed encrypted vault export.
//!   Enforces exactly two distinct recipients (`MasterPubkey` +
//!   `RecoveryPublicKey`) and non-zero `secret_count`.
//!
//! ## Entities
//!
//! - [`restore_plan::RestorePlan`] — previewed restore diff; expires after
//!   10 minutes.
//! - [`anacron_state::AnacronState`] — persisted scheduler state (last-backup
//!   timestamp + pending-change counter).
//!
//! ## Value Objects
//!
//! - [`recipient::BackupRecipient`] — `MasterPubkey | RecoveryPublicKey`.
//! - [`trigger::BackupTrigger`] — `ChangeTriggered | IdleTriggered |
//!   AnacronTriggered | Manual`.
//! - [`artifact::BackupArtifact`] — on-disk artifact descriptor with
//!   encrypt-then-MAC flag (always `true`, ADR-0006 Amendment).
//! - [`restore_mode::RestoreMode`] — conflict-resolution strategy.
//!
//! ## Domain Services
//!
//! - [`scheduler::BackupScheduler`] — pure decision logic: evaluates three
//!   trigger rules (change → idle → anacron) in priority order.
//! - [`planner::RestorePlanner`] — diffs backup secrets against live vault
//!   state to produce a [`restore_plan::RestorePlan`].
//!
//! ## Error type
//!
//! - [`error::BackupError`] — domain-level failures (duplicate recipients,
//!   zero secret count, expired plan).
//!
//! ## Cross-context relationships (docs/arch/domain/context-map.md)
//!
//! - **CF downstream** from SecretStorage — reads vault state for Backup export
//! - **SK shared kernel** with AuditCompliance — `HmacSignature` shape
//! - **C/S downstream** from PolicyPermissions — reads scheduling parameters

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

pub mod anacron_state;
pub mod artifact;
pub mod backup;
pub mod error;
pub mod planner;
pub mod recipient;
pub mod restore_mode;
pub mod restore_plan;
pub mod scheduler;
pub mod trigger;
