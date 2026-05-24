//! Integration tests for [`MockOobNotifier`] and [`PendingChallengeRegistry`].

use std::time::Duration;

use merkle_adapter_oob::mock::{MockOobNotifier, denied_resolution, expired_resolution};
use merkle_adapter_oob::pending::PendingChallengeRegistry;
use merkle_domain_access_mediation::oob::resolution::OobResolution;
use merkle_ports::OobNotifier as _;
use merkle_types::{ChallengeId, OobChallengeOutcome, Rfc3339Timestamp};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cid(suffix: u8) -> ChallengeId {
    format!("018f4c1a-0000-7000-8000-0000000000{suffix:02x}")
        .parse()
        .expect("parse challenge id")
}

fn approved_resolution(id: ChallengeId) -> OobResolution {
    OobResolution::new(
        id,
        OobChallengeOutcome::Approved,
        Some(Rfc3339Timestamp::now()),
        Some([0xAB; 64]),
    )
    .expect("approved resolution is valid")
}

// ---------------------------------------------------------------------------
// MockOobNotifier tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mock_dispatch_always_returns_ok() {
    use merkle_domain_access_mediation::companion_device::CompanionDevice;
    use merkle_domain_access_mediation::oob::challenge::OobChallenge;
    use merkle_types::{
        CompanionDeviceClass, Handle, NamespaceId, OobChannel, Sensitivity, UuidV7,
    };

    let notifier = MockOobNotifier::new();

    let challenge = OobChallenge {
        challenge_id: cid(0x01),
        namespace_id: "018f4c1a-0000-7000-8000-000000000010"
            .parse::<NamespaceId>()
            .expect("namespace id"),
        secret_handle: "vault://prod/ssh-key/bastion"
            .parse::<Handle>()
            .expect("handle"),
        sensitivity: Sensitivity::High,
        oob_channel: OobChannel::DesktopNotif,
        expires_at: Rfc3339Timestamp::now(),
        request_nonce: [0u8; 32],
        envelope: None,
    };

    let device = CompanionDevice {
        device_id: UuidV7::new(),
        ed25519_pubkey: [0u8; 32],
        x25519_pubkey: [0u8; 32],
        class: CompanionDeviceClass::Software,
        attestation_chain: vec![],
        enrolled_at: Rfc3339Timestamp::now(),
        revoked_at: None,
    };

    let result = notifier.dispatch(&challenge, &device).await;
    assert!(result.is_ok(), "dispatch must always succeed on mock");
}

#[tokio::test]
async fn mock_await_resolution_returns_preloaded_approved() {
    let notifier = MockOobNotifier::new();
    let id = cid(0x02);

    // ChallengeId is Copy; approved_resolution takes ownership.
    notifier.preload(id, approved_resolution(id));

    let res = notifier
        .await_resolution(id, Duration::from_secs(1))
        .await
        .expect("resolution must be returned");

    assert!(res.is_approved());
    assert_eq!(res.outcome, OobChallengeOutcome::Approved);
}

#[tokio::test]
async fn mock_await_resolution_returns_preloaded_denied() {
    let notifier = MockOobNotifier::new();
    let id = cid(0x03);

    notifier.preload(id, denied_resolution(id));

    let res = notifier
        .await_resolution(id, Duration::from_secs(1))
        .await
        .expect("denied resolution must be returned");

    assert!(!res.is_approved());
    assert_eq!(res.outcome, OobChallengeOutcome::Denied);
}

#[tokio::test]
async fn mock_await_resolution_returns_preloaded_expired() {
    let notifier = MockOobNotifier::new();
    let id = cid(0x04);

    notifier.preload(id, expired_resolution(id));

    let res = notifier
        .await_resolution(id, Duration::from_secs(1))
        .await
        .expect("expired resolution must be returned");

    assert_eq!(res.outcome, OobChallengeOutcome::Expired);
}

#[tokio::test]
async fn mock_await_resolution_times_out_when_nothing_preloaded() {
    use merkle_ports::error::OobError;

    let notifier = MockOobNotifier::new();
    let id = cid(0x05);

    let result = notifier
        .await_resolution(id, Duration::from_millis(10))
        .await;

    assert!(
        matches!(result, Err(OobError::Timeout)),
        "expected OobError::Timeout, got {result:?}",
    );
}

#[tokio::test]
async fn mock_preload_is_consumed_on_first_await() {
    use merkle_ports::error::OobError;

    let notifier = MockOobNotifier::new();
    let id = cid(0x06);
    notifier.preload(id, approved_resolution(id));

    // First call succeeds.
    let first = notifier.await_resolution(id, Duration::from_secs(1)).await;
    assert!(first.is_ok());

    // Second call times out — the preloaded entry was consumed.
    let second = notifier
        .await_resolution(id, Duration::from_millis(10))
        .await;
    assert!(matches!(second, Err(OobError::Timeout)));
}

#[tokio::test]
async fn mock_available_always_true() {
    let notifier = MockOobNotifier::new();
    assert!(notifier.available().await);
}

#[tokio::test]
async fn mock_pending_count_tracks_preloads() {
    let notifier = MockOobNotifier::new();
    assert_eq!(notifier.pending_count(), 0);

    notifier.preload(cid(0x10), approved_resolution(cid(0x10)));
    notifier.preload(cid(0x11), denied_resolution(cid(0x11)));
    assert_eq!(notifier.pending_count(), 2);

    let _ = notifier
        .await_resolution(cid(0x10), Duration::from_secs(1))
        .await;
    assert_eq!(notifier.pending_count(), 1);
}

// ---------------------------------------------------------------------------
// PendingChallengeRegistry tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registry_register_then_resolve_delivers_resolution() {
    let registry = PendingChallengeRegistry::new();
    let id = cid(0x20);
    let resolution = approved_resolution(id);
    let expected_outcome = resolution.outcome;

    let rx = registry.register(id);
    registry.resolve(id, resolution);

    let received = rx.await.expect("receiver must not be dropped");
    assert_eq!(received.outcome, expected_outcome);
}

#[tokio::test]
async fn registry_cancel_causes_receiver_to_error() {
    let registry = PendingChallengeRegistry::new();
    let id = cid(0x21);

    let rx = registry.register(id);
    registry.cancel(&id);

    assert!(
        rx.await.is_err(),
        "cancelled receiver should return RecvError",
    );
}

#[tokio::test]
async fn registry_resolve_with_no_registration_is_noop() {
    let registry = PendingChallengeRegistry::new();
    let id = cid(0x22);
    let resolution = denied_resolution(id);

    // Should not panic even when nothing is registered.
    registry.resolve(id, resolution);
    assert!(registry.is_empty());
}

#[tokio::test]
async fn registry_len_and_is_empty_reflect_state() {
    let registry = PendingChallengeRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);

    let id_a = cid(0x30);
    let id_b = cid(0x31);
    let _rx_a = registry.register(id_a);
    let _rx_b = registry.register(id_b);
    assert_eq!(registry.len(), 2);
    assert!(!registry.is_empty());

    registry.resolve(id_a, approved_resolution(id_a));
    assert_eq!(registry.len(), 1);
}

#[tokio::test]
async fn registry_double_register_replaces_sender() {
    let registry = PendingChallengeRegistry::new();
    let id = cid(0x40);

    let first_rx = registry.register(id);
    let second_rx = registry.register(id); // replaces the first

    // First receiver sees a recv error (sender was dropped).
    assert!(first_rx.await.is_err());

    // Resolve through the second registration.
    let resolution = denied_resolution(id);
    registry.resolve(id, resolution);

    let received = second_rx.await.expect("second receiver must succeed");
    assert_eq!(received.outcome, OobChallengeOutcome::Denied);
}
