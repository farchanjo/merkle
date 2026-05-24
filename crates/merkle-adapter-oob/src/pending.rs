//! In-memory registry tracking pending OOB challenges awaiting resolution.
//!
//! [`PendingChallengeRegistry`] is the rendezvous point between the
//! channel implementation that dispatches a challenge and the
//! `await_resolution` call that waits for the companion device to respond.

use std::collections::HashMap;

use merkle_domain_access_mediation::oob::resolution::OobResolution;
use merkle_types::ChallengeId;
use parking_lot::Mutex;
use tokio::sync::oneshot;

/// Registry that maps each pending [`ChallengeId`] to a one-shot sender.
///
/// Thread-safe: internally guarded by a [`parking_lot::Mutex`].  Guards are
/// never held across `.await` points.
#[derive(Debug, Default)]
pub struct PendingChallengeRegistry {
    inner: Mutex<HashMap<ChallengeId, oneshot::Sender<OobResolution>>>,
}

impl PendingChallengeRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new pending challenge and return the receiver half.
    ///
    /// The caller awaits the returned [`oneshot::Receiver`]; when
    /// [`resolve`](Self::resolve) is called with the same `id`, the
    /// resolution is delivered through the channel.
    ///
    /// If an entry with the same `id` already exists it is evicted and
    /// replaced; the old sender is dropped (its receiver will see a
    /// receive error).
    pub fn register(&self, id: ChallengeId) -> oneshot::Receiver<OobResolution> {
        let (tx, rx) = oneshot::channel();
        self.inner.lock().insert(id, tx);
        rx
    }

    /// Deliver a resolution to the waiting receiver.
    ///
    /// If no receiver is registered for `id` (already resolved, cancelled,
    /// or never registered), the call is a no-op.
    pub fn resolve(&self, id: ChallengeId, res: OobResolution) {
        if let Some(tx) = self.inner.lock().remove(&id) {
            // Ignore send errors: the receiver may have been dropped if
            // the caller timed out or was cancelled.
            let _ = tx.send(res);
        }
    }

    /// Cancel a pending challenge, dropping the sender without delivering
    /// a resolution.
    pub fn cancel(&self, id: &ChallengeId) {
        self.inner.lock().remove(id);
    }

    /// Returns the number of currently-pending challenges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Returns `true` when no challenges are pending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}
