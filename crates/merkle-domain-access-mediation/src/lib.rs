//! # merkle-domain-access-mediation
//!
//! **Access Mediation** bounded context.
//! See `docs/arch/domain/access-mediation.md` and
//! `docs/arch/schemas/access_mediation/` for the canonical narrative and
//! CUE type shapes.
//!
//! ## Module map
//!
//! | Module | DDD Role | Contents |
//! |---|---|---|
//! | [`reveal_request`] | AggregateRoot | `RevealRequest` — orchestrates Operator Confirmation + OOB lifecycle |
//! | [`reveal_authorization`] | ValueObject | `RevealAuthorization` — Allow / Deny decision |
//! | [`operator_confirmation`] | ValueObject | `OperatorConfirmation`, `SignedConfigFlag` |
//! | [`companion_socket_session`] | Entity | `CompanionSocketSession` — authenticated socket connection |
//! | [`companion_device`] | ValueObject | `CompanionDevice` — enrollment record (ADR-0011 + ADR-0019 + ADR-0020) |
//! | [`oob::challenge`] | ValueObject | `OobChallenge` — challenge with ECIES envelope (ADR-0019) |
//! | [`oob::resolution`] | ValueObject | `OobResolution` — Ed25519-signed outcome |
//! | [`oob::ecies_envelope`] | ValueObject | `EciesEnvelope` — X25519/XChaCha20-Poly1305 payload (ADR-0019) |
//! | [`use_token`] | Entity | `UseToken` — single-use 60s opaque authorization |
//! | [`tempfile`] | Entity | `Tempfile` — on-disk Secret materialization (mode 0600) |
//! | [`fifo`] | Entity | `Fifo` — named-pipe one-read-then-removed Secret |
//! | [`proxy_executor`] | ValueObject | `ProxyExecutor`, `ProxyToolName` — proxy tool config |
//! | [`decision`] | DomainService | `evaluate` — pure reveal authorization function |
//! | [`error`] | — | `DomainError` |
//!
//! ## Cross-context relationships (docs/arch/domain/context-map.md)
//!
//! - **C/S downstream** from SecretStorage — calls in to resolve Handle → PrivateBlob
//! - **C/S downstream** from PolicyPermissions — every proxy call is gated by policy
//! - **C/S downstream** to AuditCompliance — emits AuditEntry on every operation

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod companion_device;
pub mod companion_socket_session;
pub mod decision;
pub mod error;
pub mod fifo;
pub mod oob;
pub mod operator_confirmation;
pub mod proxy_executor;
pub mod reveal_authorization;
pub mod reveal_request;
pub mod tempfile;
pub mod use_token;
