//! # merkle-domain-identity
//!
//! **Identity and Sealing** bounded context — the Rust mirror of
//! `docs/arch/domain/identity-and-sealing.md`.
//!
//! This crate owns the entire key hierarchy of Merkle: generation, wrapping,
//! persistence strategy, and the sealed/unsealed lifecycle of the Vault Agent.
//! It intentionally excludes knowledge of individual Secrets, their categories,
//! or any application-level business logic.
//!
//! ## DDD role map
//!
//! | Type | DDD Role | Module |
//! |---|---|---|
//! | [`VaultIdentity`] | AggregateRoot | [`vault_identity`] |
//! | [`MasterKey`] | Entity | [`master_key`] |
//! | [`VaultRootKey`] | Entity | [`vault_root_key`] |
//! | [`NamespaceDek`] | Entity | [`namespace_dek`] |
//! | [`RecoveryPublicKey`] | Entity (public half) | [`recovery_key`] |
//! | [`RecoveryKey`] | Entity (private — transient) | [`recovery_key`] |
//! | [`SealedState`] | ValueObject | [`sealed_state`] |
//! | [`UnsealPreconditions`] | ValueObject | [`unseal_preconditions`] |
//! | [`Argon2idParams`] | ValueObject | [`master_key`] |
//! | [`KeychainEntry`] | ValueObject | [`keychain_entry`] |
//! | [`WrappedVaultRootKey`] | ValueObject | [`vault_root_key`] |
//! | [`UnsealProtocol`] | DomainService | [`unseal_protocol`] |
//!
//! ## Cross-context relationships
//!
//! - **C/S upstream** to SecretStorage — provides unwrapped [`NamespaceDek`]s.
//! - **Shared Kernel** with AuditCompliance — `HmacSignature` shape.
//!
//! ## References
//!
//! - Domain narrative: `docs/arch/domain/identity-and-sealing.md`
//! - ADR-0004: XChaCha20-Poly1305 AEAD
//! - ADR-0005: Argon2id KDF (passphrase fallback)
//! - ADR-0015: Rust `keyring` crate for multi-OS keychain

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

pub mod error;
pub mod keychain_entry;
pub mod master_key;
pub mod namespace_dek;
pub mod recovery_key;
pub mod sealed_state;
pub mod unseal_preconditions;
pub mod unseal_protocol;
pub mod vault_identity;
pub mod vault_root_key;

pub use error::DomainError;
pub use keychain_entry::{KeychainEntry, KEYCHAIN_ACCOUNT_MASTER_KEY, KEYCHAIN_SERVICE};
pub use master_key::{Argon2idParams, MasterKey, MIN_M_COST, MIN_P_COST, MIN_T_COST};
pub use namespace_dek::{NamespaceDek, WrappedDek};
pub use recovery_key::{RecoveryKey, RecoveryPublicKey};
pub use sealed_state::SealedState;
pub use unseal_preconditions::UnsealPreconditions;
pub use unseal_protocol::UnsealProtocol;
pub use vault_identity::{UnsealGuard, VaultIdentity};
pub use vault_root_key::{VaultRootKey, WrapMethod, WrappedVaultRootKey};
