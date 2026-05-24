//! `SealedState` — lifecycle phase enum for the Vault Agent.
//!
//! Mirrors `docs/arch/schemas/identity_and_sealing/sealed_state.cue`.

use serde::{Deserialize, Serialize};

/// The lifecycle phase of the Vault Agent with respect to the Vault Root Key.
///
/// ## State machine
///
/// ```text
///   sealed ──────────────────────── unsealing
///     ^                            /       \
///     │         (load failed)     /         \  (load ok)
///     │                          v           v
///   shutting_down ◄──── unsealed
///         │
///         │  (key zeroed)
///         v
///       sealed
/// ```
///
/// Permitted transitions (see [`SealedState::can_transition_to`]):
///
/// | From           | To             | Trigger                                |
/// |----------------|----------------|----------------------------------------|
/// | `Sealed`       | `Unsealing`    | Unseal command received                |
/// | `Unsealing`    | `Unsealed`     | VRK loaded into protected memory       |
/// | `Unsealing`    | `Sealed`       | Unseal failed; key material zeroed     |
/// | `Unsealed`     | `ShuttingDown` | Agent preparing to stop                |
/// | `ShuttingDown` | `Sealed`       | Key material zeroed; agent exiting     |
///
/// ```
/// use merkle_domain_identity::SealedState;
///
/// assert!(SealedState::Sealed.can_transition_to(SealedState::Unsealing));
/// assert!(!SealedState::Sealed.can_transition_to(SealedState::Unsealed));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedState {
    /// Default on agent boot. Vault Root Key is absent from memory.
    /// All operations except `unseal` and `doctor` are rejected.
    Sealed,
    /// Transitional phase. An unseal sequence has started but has not yet
    /// loaded the Vault Root Key into protected memory.
    Unsealing,
    /// Vault Root Key is loaded in (optionally mlocked) memory.
    /// Read and write operations are permitted.
    Unsealed,
    /// Agent is preparing to stop. Key material will be zeroed before exit.
    ShuttingDown,
}

impl SealedState {
    /// Return `true` if the transition from `self` to `next` is permitted by
    /// the domain state machine.
    ///
    /// ```
    /// use merkle_domain_identity::SealedState;
    ///
    /// // Valid edges
    /// assert!(SealedState::Sealed.can_transition_to(SealedState::Unsealing));
    /// assert!(SealedState::Unsealing.can_transition_to(SealedState::Unsealed));
    /// assert!(SealedState::Unsealing.can_transition_to(SealedState::Sealed));
    /// assert!(SealedState::Unsealed.can_transition_to(SealedState::ShuttingDown));
    /// assert!(SealedState::ShuttingDown.can_transition_to(SealedState::Sealed));
    ///
    /// // Invalid edges
    /// assert!(!SealedState::Sealed.can_transition_to(SealedState::Unsealed));
    /// assert!(!SealedState::Unsealed.can_transition_to(SealedState::Sealed));
    /// assert!(!SealedState::Sealed.can_transition_to(SealedState::ShuttingDown));
    /// ```
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Sealed, Self::Unsealing)
                | (Self::Unsealing, Self::Unsealed | Self::Sealed)
                | (Self::Unsealed, Self::ShuttingDown)
                | (Self::ShuttingDown, Self::Sealed)
        )
    }

    /// Return the set of [`merkle_types::AuditOp`] values that are permitted
    /// while the vault is in this state.
    ///
    /// In `Sealed` and `Unsealing` states only lifecycle operations
    /// (`Unseal`, `Doctor`) are permitted. In `Unsealed` all 30 operations
    /// are available (AccessMediation enforces per-op policy; this is a coarse
    /// gate only). In `ShuttingDown` only `Unseal` (idempotent) and `Doctor`
    /// are permitted.
    #[must_use]
    pub fn allowed_ops(self) -> &'static [merkle_types::AuditOp] {
        use merkle_types::AuditOp;

        /// All 31 AuditOp variants in declaration order.
        static ALL: &[AuditOp] = &[
            AuditOp::AuditQuery,
            AuditOp::Init,
            AuditOp::Backup,
            AuditOp::Bind,
            AuditOp::CategoryCreate,
            AuditOp::CryptoDecrypt,
            AuditOp::CryptoSign,
            AuditOp::CrossEnvWarning,
            AuditOp::Delete,
            AuditOp::Describe,
            AuditOp::DisasterRecovery,
            AuditOp::Doctor,
            AuditOp::Get,
            AuditOp::HttpDownload,
            AuditOp::HttpRequest,
            AuditOp::HttpUpload,
            AuditOp::List,
            AuditOp::NamespaceCreate,
            AuditOp::PortForward,
            AuditOp::Put,
            AuditOp::Restore,
            AuditOp::Reveal,
            AuditOp::Rotate,
            AuditOp::Search,
            AuditOp::Spawn,
            AuditOp::SshCopy,
            AuditOp::SshExec,
            AuditOp::Unseal,
            AuditOp::Use,
            AuditOp::UseTokenResolved,
            AuditOp::WriteTempfile,
        ];

        /// Lifecycle-only operations (unseal + doctor).
        static LIFECYCLE: &[AuditOp] = &[AuditOp::Unseal, AuditOp::Doctor];

        match self {
            // While sealed or mid-unseal, only lifecycle ops are permitted.
            Self::Sealed | Self::Unsealing | Self::ShuttingDown => LIFECYCLE,
            // While unsealed, all operations are available.
            Self::Unsealed => ALL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// All 5 valid edges are permitted.
    #[test]
    fn valid_transitions() {
        let valid = [
            (SealedState::Sealed, SealedState::Unsealing),
            (SealedState::Unsealing, SealedState::Unsealed),
            (SealedState::Unsealing, SealedState::Sealed),
            (SealedState::Unsealed, SealedState::ShuttingDown),
            (SealedState::ShuttingDown, SealedState::Sealed),
        ];
        for (from, to) in valid {
            assert!(
                from.can_transition_to(to),
                "{from:?} -> {to:?} should be valid"
            );
        }
    }

    /// All self-transitions and invalid cross-edges are forbidden.
    #[test]
    fn invalid_transitions() {
        use SealedState::*;
        let all = [Sealed, Unsealing, Unsealed, ShuttingDown];
        let valid_set = [
            (Sealed, Unsealing),
            (Unsealing, Unsealed),
            (Unsealing, Sealed),
            (Unsealed, ShuttingDown),
            (ShuttingDown, Sealed),
        ];
        for from in all {
            for to in all {
                let expected = valid_set.contains(&(from, to));
                assert_eq!(
                    from.can_transition_to(to),
                    expected,
                    "{from:?} -> {to:?}: expected {expected}"
                );
            }
        }
    }

    /// Sealed and Unsealing only allow unseal + doctor.
    #[test]
    fn sealed_allowed_ops_subset() {
        use merkle_types::AuditOp;
        for state in [SealedState::Sealed, SealedState::Unsealing] {
            let ops = state.allowed_ops();
            assert!(
                ops.contains(&AuditOp::Unseal),
                "{state:?} must allow Unseal"
            );
            assert!(
                ops.contains(&AuditOp::Doctor),
                "{state:?} must allow Doctor"
            );
            assert!(
                !ops.contains(&AuditOp::Reveal),
                "{state:?} must deny Reveal"
            );
        }
    }

    /// Unsealed allows all 31 operations; ShuttingDown restricts to lifecycle ops.
    #[test]
    fn unsealed_allows_all_ops() {
        assert_eq!(SealedState::Unsealed.allowed_ops().len(), 31);
        assert_eq!(SealedState::ShuttingDown.allowed_ops().len(), 2);
    }

    fn arb_state() -> impl Strategy<Value = SealedState> {
        prop_oneof![
            Just(SealedState::Sealed),
            Just(SealedState::Unsealing),
            Just(SealedState::Unsealed),
            Just(SealedState::ShuttingDown),
        ]
    }

    proptest! {
        /// No state can transition to itself (self-loops are forbidden).
        #[test]
        fn no_self_loops(state in arb_state()) {
            prop_assert!(!state.can_transition_to(state));
        }

        /// The only bidirectional pairs allowed by the state machine are the
        /// explicitly modelled rollback edges:
        ///   - Sealed ↔ Unsealing  (forward: unseal command; backward: failed unseal)
        ///   - ShuttingDown ↔ Sealed is NOT bidirectional (ShuttingDown→Sealed only)
        ///
        /// All other bidirectional pairs are forbidden.
        #[test]
        fn only_expected_bidirectional_edges(a in arb_state(), b in arb_state()) {
            if a.can_transition_to(b) && b.can_transition_to(a) {
                // The only expected bidirectional pair is Sealed ↔ Unsealing.
                let expected = (a == SealedState::Sealed && b == SealedState::Unsealing)
                    || (a == SealedState::Unsealing && b == SealedState::Sealed);
                prop_assert!(
                    expected,
                    "unexpected bidirectional edge: {a:?} <-> {b:?}"
                );
            }
        }
    }
}
