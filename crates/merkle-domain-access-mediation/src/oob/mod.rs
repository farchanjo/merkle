//! Out-of-Band (OOB) Confirmation types for the Access Mediation context.
//!
//! - [`challenge`] — `OobChallenge` value object with ECIES envelope support.
//! - [`resolution`] — `OobResolution` value object with Ed25519 signature field.
//! - [`ecies_envelope`] — `EciesEnvelope` value object per ADR-0019.

pub mod challenge;
pub mod ecies_envelope;
pub mod resolution;
