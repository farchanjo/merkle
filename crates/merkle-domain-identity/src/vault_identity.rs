//! `VaultIdentity` — AggregateRoot of the Identity and Sealing bounded context.
//!
//! Owns the sealed/unsealed lifecycle of the Vault Agent.  When in the
//! `Unsealed` state it holds the `VaultRootKey` in (optionally mlocked)
//! memory.  All state transitions are guarded by the domain state machine
//! encoded in [`crate::SealedState::can_transition_to`].

use std::fmt;

use serde::{Deserialize, Serialize};

use merkle_types::{Rfc3339Timestamp, UuidV7};

use crate::{
    DomainError, KeychainEntry, SealedState, UnsealPreconditions, VaultRootKey,
    recovery_key::RecoveryPublicKey,
};

/// The single aggregate root for a Merkle vault's cryptographic identity.
///
/// Created once at `merkle init` and mutated only on master-key rotation,
/// recovery-key rotation, or seal/unseal lifecycle events.
///
/// ## Invariants
///
/// 1. `vault_root_key.is_some() == matches!(state, SealedState::Unsealed)`.
///    Any transition that violates this is rejected with
///    [`DomainError::VaultRootKeyInvariant`].
/// 2. The `RecoveryPublicKey` stored here must always match the private
///    recovery key held by the operator.
/// 3. The state machine is the sole authority for allowed transitions.
///
/// ```
/// use merkle_domain_identity::{VaultIdentity, UnsealPreconditions, VaultRootKey};
/// use merkle_types::{SecurityProfile, Rfc3339Timestamp};
/// use merkle_domain_identity::KeychainEntry;
/// use merkle_domain_identity::recovery_key::RecoveryPublicKey;
///
/// let keychain_ref = KeychainEntry::for_master_key(1, Rfc3339Timestamp::now());
/// let recovery_pubkey = RecoveryPublicKey::new(
///     "age1test".to_owned(),
///     "SHA256:x=".to_owned(),
///     Rfc3339Timestamp::now(),
/// );
/// let mut identity = VaultIdentity::new(keychain_ref, recovery_pubkey);
///
/// let pre = UnsealPreconditions {
///     security_profile: SecurityProfile::Balanced,
///     mlock_succeeded: true,
///     entropy_seeded: true,
///     keychain_reachable: true,
/// };
/// identity.begin_unseal(pre).unwrap();
/// identity.complete_unseal(VaultRootKey::generate()).unwrap();
/// assert!(identity.is_unsealed());
/// ```
#[derive(Serialize, Deserialize)]
pub struct VaultIdentity {
    /// Immutable vault identifier (UUIDv7), set at `merkle init`.
    id: UuidV7,

    /// RFC 3339 timestamp of vault initialization.
    created_at: Rfc3339Timestamp,

    /// Current lifecycle phase.
    state: SealedState,

    /// Reference to the active Master Key entry in the OS keychain.
    master_key_keychain_ref: KeychainEntry,

    /// The age X25519 public recipient used for disaster recovery and backups.
    recovery_pubkey: RecoveryPublicKey,

    /// Timestamp of the last successful unseal.  Absent until the first unseal.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_unsealed_at: Option<Rfc3339Timestamp>,

    /// The Vault Root Key — present only when `state == Unsealed`.
    ///
    /// Never serialized; lives in process memory only.
    #[serde(skip)]
    vault_root_key: Option<VaultRootKey>,
}

impl fmt::Debug for VaultIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultIdentity")
            .field("id", &self.id)
            .field("created_at", &self.created_at)
            .field("state", &self.state)
            .field("master_key_keychain_ref", &self.master_key_keychain_ref)
            .field("recovery_pubkey", &self.recovery_pubkey)
            .field("last_unsealed_at", &self.last_unsealed_at)
            .field("vault_root_key", &"[REDACTED]")
            .finish()
    }
}

impl VaultIdentity {
    /// Create a new `VaultIdentity` in the `Sealed` state.
    ///
    /// Called exactly once at `merkle init`.
    #[must_use]
    pub fn new(master_key_keychain_ref: KeychainEntry, recovery_pubkey: RecoveryPublicKey) -> Self {
        Self {
            id: UuidV7::new(),
            created_at: Rfc3339Timestamp::now(),
            state: SealedState::Sealed,
            master_key_keychain_ref,
            recovery_pubkey,
            last_unsealed_at: None,
            vault_root_key: None,
        }
    }

    // -----------------------------------------------------------------------
    // State machine commands
    // -----------------------------------------------------------------------

    /// Initiate the unseal sequence.
    ///
    /// Validates `preconditions` against the Rego policy rules encoded in
    /// [`UnsealPreconditions::validate`], then transitions `Sealed →
    /// Unsealing`.
    ///
    /// If the vault is already `Unsealed`, returns
    /// [`DomainError::AlreadyUnsealed`] (idempotency — caller may treat this
    /// as success).
    ///
    /// # Errors
    ///
    /// - [`DomainError::AlreadyUnsealed`] — vault is already unsealed.
    /// - [`DomainError::InvalidStateTransition`] — current state does not
    ///   permit transitioning to `Unsealing`.
    /// - [`DomainError::UnsealPreconditionFailed`] — a precondition check
    ///   failed.
    pub fn begin_unseal(&mut self, preconditions: UnsealPreconditions) -> Result<(), DomainError> {
        if self.state == SealedState::Unsealed {
            return Err(DomainError::AlreadyUnsealed);
        }

        if !self.state.can_transition_to(SealedState::Unsealing) {
            return Err(DomainError::InvalidStateTransition {
                from: self.state,
                to: SealedState::Unsealing,
            });
        }

        // Evaluate preconditions before touching any key material.
        preconditions.validate()?;

        self.state = SealedState::Unsealing;
        Ok(())
    }

    /// Complete the unseal sequence by supplying the decrypted Vault Root Key.
    ///
    /// Transitions `Unsealing → Unsealed` and loads `vrk` into memory.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidStateTransition`] — not currently `Unsealing`.
    /// - [`DomainError::VaultRootKeyInvariant`] — VRK was already present
    ///   (indicates a programming error).
    pub fn complete_unseal(&mut self, vrk: VaultRootKey) -> Result<(), DomainError> {
        if !self.state.can_transition_to(SealedState::Unsealed) {
            return Err(DomainError::InvalidStateTransition {
                from: self.state,
                to: SealedState::Unsealed,
            });
        }

        if self.vault_root_key.is_some() {
            return Err(DomainError::VaultRootKeyInvariant {
                detail: "VRK already present before Unsealing→Unsealed transition",
            });
        }

        self.vault_root_key = Some(vrk);
        self.state = SealedState::Unsealed;
        self.last_unsealed_at = Some(Rfc3339Timestamp::now());
        self.assert_vrk_invariant();
        Ok(())
    }

    /// Seal the vault, zeroing the Vault Root Key from memory.
    ///
    /// Valid only from `Unsealed` (via `ShuttingDown`) or from `ShuttingDown`
    /// directly. The `Unsealing → Sealed` edge is the rollback path and belongs
    /// exclusively to [`revert_to_sealed`](Self::revert_to_sealed); `seal` must
    /// NOT take it, otherwise a concurrent operator seal racing into an
    /// in-flight unseal's no-lock window would abort that unseal and corrupt the
    /// audit trail.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidStateTransition`] — state is not `Unsealed` or
    ///   `ShuttingDown` (in particular `Unsealing` and `Sealed` are rejected).
    pub fn seal(&mut self) -> Result<(), DomainError> {
        // Reject anything that is not a legitimate operator-seal origin. This is
        // what stops `seal` from consuming the `Unsealing → Sealed` rollback
        // edge that `can_transition_to` also permits.
        if !matches!(
            self.state,
            SealedState::Unsealed | SealedState::ShuttingDown
        ) {
            return Err(DomainError::InvalidStateTransition {
                from: self.state,
                to: SealedState::Sealed,
            });
        }

        // From Unsealed we must go through ShuttingDown.
        if self.state == SealedState::Unsealed {
            self.state = SealedState::ShuttingDown;
        }

        debug_assert!(self.state.can_transition_to(SealedState::Sealed));

        // Zeroize key material — Drop on VaultRootKey handles the actual zeroize.
        self.vault_root_key = None;
        self.state = SealedState::Sealed;
        self.assert_vrk_invariant();
        Ok(())
    }

    /// Transition `Unsealing → Sealed` (rollback on failed unseal).
    ///
    /// Called automatically by [`UnsealGuard`] on drop.  May also be called
    /// directly in error-recovery paths.
    ///
    /// This is a best-effort rollback: if the transition is impossible from the
    /// current state the method returns the domain error rather than panicking,
    /// allowing the caller to log and continue.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidStateTransition`] — not currently `Unsealing`.
    pub fn revert_to_sealed(&mut self) -> Result<(), DomainError> {
        if !self.state.can_transition_to(SealedState::Sealed) {
            return Err(DomainError::InvalidStateTransition {
                from: self.state,
                to: SealedState::Sealed,
            });
        }
        // Zeroize any partial key material.
        self.vault_root_key = None;
        self.state = SealedState::Sealed;
        Ok(())
    }

    /// Initiate the unseal sequence and return an [`UnsealGuard`].
    ///
    /// The guard wraps a mutable borrow of `self`.  When dropped without
    /// calling [`UnsealGuard::commit`], it automatically reverts the state
    /// back to `Sealed` — preventing the `Unsealing` state from leaking on
    /// error paths.
    ///
    /// # Errors
    ///
    /// Same as [`begin_unseal`](Self::begin_unseal).
    pub fn begin_unseal_with_guard(
        &mut self,
        preconditions: UnsealPreconditions,
    ) -> Result<UnsealGuard<'_>, DomainError> {
        self.begin_unseal(preconditions)?;
        Ok(UnsealGuard {
            identity: self,
            committed: false,
        })
    }

    /// Transition `Unsealed → ShuttingDown`.
    ///
    /// The caller must subsequently call [`seal`](Self::seal) to complete the
    /// shutdown and zero the VRK.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidStateTransition`] — not currently `Unsealed`.
    pub fn shutdown(&mut self) -> Result<(), DomainError> {
        if !self.state.can_transition_to(SealedState::ShuttingDown) {
            return Err(DomainError::InvalidStateTransition {
                from: self.state,
                to: SealedState::ShuttingDown,
            });
        }
        self.state = SealedState::ShuttingDown;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Return the unique vault identifier.
    #[must_use]
    pub fn id(&self) -> UuidV7 {
        self.id
    }

    /// Return the current sealed state.
    #[must_use]
    pub fn state(&self) -> SealedState {
        self.state
    }

    /// Return `true` if the vault is currently in `Unsealed` state.
    #[must_use]
    pub fn is_unsealed(&self) -> bool {
        self.state == SealedState::Unsealed
    }

    /// Return a reference to the keychain locator for the active Master Key.
    #[must_use]
    pub fn master_key_keychain_ref(&self) -> &KeychainEntry {
        &self.master_key_keychain_ref
    }

    /// Return a reference to the Recovery Public Key.
    #[must_use]
    pub fn recovery_pubkey(&self) -> &RecoveryPublicKey {
        &self.recovery_pubkey
    }

    /// Return the timestamp of the last successful unseal, if any.
    #[must_use]
    pub fn last_unsealed_at(&self) -> Option<Rfc3339Timestamp> {
        self.last_unsealed_at
    }

    /// Expose the Vault Root Key for cryptographic operations.
    ///
    /// Returns `None` when the vault is sealed.  **Never** store or log the
    /// returned reference.
    #[must_use]
    pub fn vault_root_key(&self) -> Option<&VaultRootKey> {
        self.vault_root_key.as_ref()
    }

    // -----------------------------------------------------------------------
    // Invariant check (private)
    // -----------------------------------------------------------------------

    /// Panic in debug builds if the VRK-presence invariant is violated.
    ///
    /// This is a belt-and-suspenders guard; the transition methods enforce the
    /// invariant structurally, so this should never fire.
    fn assert_vrk_invariant(&self) {
        debug_assert_eq!(
            self.vault_root_key.is_some(),
            self.state == SealedState::Unsealed,
            "VRK invariant violated: state={:?} vrk_present={}",
            self.state,
            self.vault_root_key.is_some()
        );
    }
}

// ---------------------------------------------------------------------------
// UnsealGuard — RAII rollback for failed unseal (ADR-0015 Amendment 3)
// ---------------------------------------------------------------------------

/// RAII guard returned by [`VaultIdentity::begin_unseal_with_guard`].
///
/// While the guard is alive the vault is in `Unsealing` state.  Dropping the
/// guard without calling [`commit`](Self::commit) automatically reverts the
/// state back to `Sealed` (i.e., calls [`VaultIdentity::revert_to_sealed`]).
///
/// This prevents leaked `Unsealing` state on `?`-propagated error paths in the
/// application layer.
///
/// ## Usage
///
/// ```rust
/// # use merkle_domain_identity::{VaultIdentity, UnsealPreconditions, VaultRootKey};
/// # use merkle_types::{SecurityProfile, Rfc3339Timestamp};
/// # use merkle_domain_identity::KeychainEntry;
/// # use merkle_domain_identity::recovery_key::RecoveryPublicKey;
/// let keychain_ref = KeychainEntry::for_master_key(1, Rfc3339Timestamp::now());
/// let recovery_pubkey = RecoveryPublicKey::new(
///     "age1test".to_owned(),
///     "SHA256:x=".to_owned(),
///     Rfc3339Timestamp::now(),
/// );
/// let mut identity = VaultIdentity::new(keychain_ref, recovery_pubkey);
/// let pre = UnsealPreconditions {
///     security_profile: SecurityProfile::Balanced,
///     mlock_succeeded: true,
///     entropy_seeded: true,
///     keychain_reachable: true,
/// };
///
/// // Guard automatically reverts if we return early without commit.
/// let guard = identity.begin_unseal_with_guard(pre).unwrap();
/// drop(guard); // ← revert_to_sealed called here
///
/// use merkle_domain_identity::SealedState;
/// assert_eq!(identity.state(), SealedState::Sealed);
/// ```
pub struct UnsealGuard<'a> {
    identity: &'a mut VaultIdentity,
    committed: bool,
}

impl UnsealGuard<'_> {
    /// Complete the unseal sequence by loading the VRK into memory.
    ///
    /// After calling `commit` the guard's drop will NOT revert the state.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidStateTransition`] — not currently `Unsealing`.
    /// - [`DomainError::VaultRootKeyInvariant`] — VRK already present.
    pub fn commit(mut self, vrk: VaultRootKey) -> Result<(), DomainError> {
        self.identity.complete_unseal(vrk)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for UnsealGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // Best-effort rollback — ignore errors (state may already be Sealed
            // if commit failed and the caller reset it manually).
            let _ = self.identity.revert_to_sealed();
        }
    }
}

#[cfg(test)]
mod tests {
    use merkle_types::SecurityProfile;

    use super::*;

    fn ok_preconditions() -> UnsealPreconditions {
        UnsealPreconditions {
            security_profile: SecurityProfile::Balanced,
            mlock_succeeded: true,
            entropy_seeded: true,
            keychain_reachable: true,
        }
    }

    fn make_identity() -> VaultIdentity {
        VaultIdentity::new(
            KeychainEntry::for_master_key(1, Rfc3339Timestamp::now()),
            RecoveryPublicKey::new(
                "age1test".to_owned(),
                "SHA256:x=".to_owned(),
                Rfc3339Timestamp::now(),
            ),
        )
    }

    #[test]
    fn new_identity_is_sealed() {
        let id = make_identity();
        assert_eq!(id.state(), SealedState::Sealed);
        assert!(!id.is_unsealed());
        assert!(id.vault_root_key().is_none());
    }

    #[test]
    fn full_unseal_sequence_succeeds() {
        let mut id = make_identity();
        id.begin_unseal(ok_preconditions()).unwrap();
        assert_eq!(id.state(), SealedState::Unsealing);

        let vrk = VaultRootKey::generate();
        id.complete_unseal(vrk).unwrap();
        assert_eq!(id.state(), SealedState::Unsealed);
        assert!(id.is_unsealed());
        assert!(id.vault_root_key().is_some());
        assert!(id.last_unsealed_at().is_some());
    }

    #[test]
    fn seal_after_unseal_zeros_vrk() {
        let mut id = make_identity();
        id.begin_unseal(ok_preconditions()).unwrap();
        id.complete_unseal(VaultRootKey::generate()).unwrap();

        id.seal().unwrap();
        assert_eq!(id.state(), SealedState::Sealed);
        assert!(id.vault_root_key().is_none());
    }

    #[test]
    fn second_unseal_is_idempotent_error() {
        let mut id = make_identity();
        id.begin_unseal(ok_preconditions()).unwrap();
        id.complete_unseal(VaultRootKey::generate()).unwrap();

        let err = id.begin_unseal(ok_preconditions()).unwrap_err();
        assert!(matches!(err, DomainError::AlreadyUnsealed));
    }

    #[test]
    fn begin_unseal_from_wrong_state_fails() {
        let mut id = make_identity();
        id.begin_unseal(ok_preconditions()).unwrap();
        // Now in Unsealing; begin_unseal again should fail.
        let err = id.begin_unseal(ok_preconditions()).unwrap_err();
        assert!(matches!(err, DomainError::InvalidStateTransition { .. }));
    }

    #[test]
    fn failed_precondition_blocks_unseal() {
        let mut id = make_identity();
        let bad_pre = UnsealPreconditions {
            security_profile: SecurityProfile::Balanced,
            mlock_succeeded: false,
            entropy_seeded: false, // fatal
            keychain_reachable: true,
        };
        assert!(id.begin_unseal(bad_pre).is_err());
        // State must still be Sealed.
        assert_eq!(id.state(), SealedState::Sealed);
    }

    #[test]
    fn debug_redacts_vrk() {
        let mut id = make_identity();
        id.begin_unseal(ok_preconditions()).unwrap();
        id.complete_unseal(VaultRootKey::generate()).unwrap();
        let debug = format!("{id:?}");
        assert!(
            debug.contains("[REDACTED]"),
            "VRK must be redacted in Debug"
        );
    }

    #[test]
    fn shutdown_then_seal() {
        let mut id = make_identity();
        id.begin_unseal(ok_preconditions()).unwrap();
        id.complete_unseal(VaultRootKey::generate()).unwrap();

        id.shutdown().unwrap();
        assert_eq!(id.state(), SealedState::ShuttingDown);

        id.seal().unwrap();
        assert_eq!(id.state(), SealedState::Sealed);
        assert!(id.vault_root_key().is_none());
    }

    /// `seal()` must NOT consume the `Unsealing → Sealed` rollback edge — that
    /// belongs to `revert_to_sealed`. A concurrent operator seal reaching an
    /// in-flight unseal (state `Unsealing`) must be rejected so it cannot hijack
    /// the unseal and corrupt the audit trail.
    #[test]
    fn seal_from_unsealing_is_rejected() {
        let mut id = make_identity();
        id.begin_unseal(ok_preconditions()).unwrap();
        assert_eq!(id.state(), SealedState::Unsealing);

        let err = id.seal().unwrap_err();
        assert!(
            matches!(err, DomainError::InvalidStateTransition { .. }),
            "seal() from Unsealing must be rejected, got {err:?}"
        );
        // The unseal is untouched — still Unsealing — and the dedicated rollback
        // path still works.
        assert_eq!(id.state(), SealedState::Unsealing);
        id.revert_to_sealed().unwrap();
        assert_eq!(id.state(), SealedState::Sealed);
    }

    /// `seal()` on an already-`Sealed` vault is rejected (not a silent no-op).
    #[test]
    fn seal_from_sealed_is_rejected() {
        let mut id = make_identity();
        assert_eq!(id.state(), SealedState::Sealed);
        let err = id.seal().unwrap_err();
        assert!(matches!(err, DomainError::InvalidStateTransition { .. }));
    }

    // -----------------------------------------------------------------------
    // UnsealGuard tests (B3 — ADR-0015 Amendment 3)
    // -----------------------------------------------------------------------

    /// Drop-without-commit reverts `Unsealing → Sealed`.
    #[test]
    fn unseal_guard_drop_without_commit_reverts_to_sealed() {
        let mut id = make_identity();

        {
            // The guard mutably borrows `id`; we cannot call id.state() while
            // the guard is alive. Drop it first, then assert.
            let guard = id.begin_unseal_with_guard(ok_preconditions()).unwrap();
            drop(guard); // revert_to_sealed called here
        }

        assert_eq!(
            id.state(),
            SealedState::Sealed,
            "state must revert to Sealed after guard drop without commit"
        );
        assert!(id.vault_root_key().is_none());
    }

    /// Two consecutive failed unseals do not produce an invalid state
    /// transition error on the second attempt.
    #[test]
    fn two_consecutive_failed_unseals_do_not_leave_invalid_state() {
        let mut id = make_identity();

        // First failed unseal.
        {
            let guard = id.begin_unseal_with_guard(ok_preconditions()).unwrap();
            drop(guard); // Revert → Sealed.
        }
        assert_eq!(id.state(), SealedState::Sealed);

        // Second attempt must succeed — state is back to Sealed.
        {
            let guard = id.begin_unseal_with_guard(ok_preconditions()).unwrap();
            drop(guard); // Revert → Sealed again.
        }
        assert_eq!(id.state(), SealedState::Sealed);
    }

    /// Commit on the guard successfully transitions to Unsealed.
    #[test]
    fn unseal_guard_commit_transitions_to_unsealed() {
        let mut id = make_identity();
        let guard = id.begin_unseal_with_guard(ok_preconditions()).unwrap();
        guard.commit(VaultRootKey::generate()).unwrap();
        assert_eq!(id.state(), SealedState::Unsealed);
        assert!(id.is_unsealed());
        assert!(id.vault_root_key().is_some());
    }

    /// `revert_to_sealed` from `Sealed` state returns an error rather than panicking.
    #[test]
    fn revert_to_sealed_from_wrong_state_returns_error() {
        let mut id = make_identity();
        // Already Sealed — can't transition Sealed → Sealed.
        let err = id.revert_to_sealed().unwrap_err();
        assert!(
            matches!(err, DomainError::InvalidStateTransition { .. }),
            "expected InvalidStateTransition, got {err:?}"
        );
    }
}
