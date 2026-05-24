//! Integration tests for `RustCryptoAdapter` (F3.C).
//!
//! Covers: AEAD, BLAKE3, Argon2id, Ed25519, ECIES, age, and random helpers.

use age::secrecy::ExposeSecret;
use merkle_adapter_crypto::RustCryptoAdapter;
use merkle_domain_identity::Argon2idParams;
use merkle_ports::{AgeIdentity, AgeRecipient, Crypto};
use proptest::prelude::*;

fn adapter() -> RustCryptoAdapter {
    RustCryptoAdapter::new()
}

// ---------------------------------------------------------------------------
// Random helpers
// ---------------------------------------------------------------------------

#[test]
fn random_bytes_lengths() {
    let a = adapter();
    let b32 = a.random_bytes_32();
    let b24 = a.random_bytes_24();
    let b16 = a.random_bytes_16();
    assert_eq!(b32.len(), 32);
    assert_eq!(b24.len(), 24);
    assert_eq!(b16.len(), 16);
}

#[test]
fn random_bytes_are_distinct_across_calls() {
    let a = adapter();
    let a1 = a.random_bytes_32();
    let a2 = a.random_bytes_32();
    assert_ne!(a1, a2, "two consecutive random_bytes_32 calls must differ");
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

#[test]
fn aead_encrypt_decrypt_round_trip() {
    let a = adapter();
    let key = [0x42u8; 32];
    let nonce = [0x11u8; 24];
    let plaintext = b"hello merkle vault";
    let aad = b"vault://test/secrets/foo";

    let ct = a.aead_encrypt(&key, &nonce, plaintext, aad).expect("encrypt ok");
    let pt = a.aead_decrypt(&key, &nonce, &ct, aad).expect("decrypt ok");
    assert_eq!(pt, plaintext);
}

#[test]
fn aead_tampered_ciphertext_rejected() {
    let a = adapter();
    let key = [0xAAu8; 32];
    let nonce = [0xBBu8; 24];
    let plaintext = b"sensitive data";
    let aad = b"test-aad";

    let mut ct = a.aead_encrypt(&key, &nonce, plaintext, aad).expect("encrypt ok");
    ct[0] ^= 0xFF;

    let err = a.aead_decrypt(&key, &nonce, &ct, aad);
    assert!(err.is_err(), "tampered ciphertext must be rejected");
}

#[test]
fn aead_wrong_aad_rejected() {
    let a = adapter();
    let key = [0x01u8; 32];
    let nonce = [0x02u8; 24];
    let plaintext = b"data";
    let aad = b"correct-aad";

    let ct = a.aead_encrypt(&key, &nonce, plaintext, aad).expect("encrypt ok");
    let err = a.aead_decrypt(&key, &nonce, &ct, b"wrong-aad");
    assert!(err.is_err(), "wrong AAD must be rejected");
}

#[test]
fn aead_wrong_key_rejected() {
    let a = adapter();
    let key1 = [0x10u8; 32];
    let key2 = [0x20u8; 32];
    let nonce = [0x30u8; 24];
    let plaintext = b"secret";
    let aad = b"";

    let ct = a.aead_encrypt(&key1, &nonce, plaintext, aad).expect("encrypt ok");
    let err = a.aead_decrypt(&key2, &nonce, &ct, aad);
    assert!(err.is_err(), "wrong key must be rejected");
}

// ---------------------------------------------------------------------------
// BLAKE3
// ---------------------------------------------------------------------------

#[test]
fn blake3_hash_deterministic() {
    let a = adapter();
    let h1 = a.blake3_hash(b"merkle");
    let h2 = a.blake3_hash(b"merkle");
    assert_eq!(h1, h2);
}

#[test]
fn blake3_hash_distinct_inputs() {
    let a = adapter();
    let h1 = a.blake3_hash(b"a");
    let h2 = a.blake3_hash(b"b");
    assert_ne!(h1, h2);
}

#[test]
fn blake3_keyed_deterministic() {
    let a = adapter();
    let key = [0xFFu8; 32];
    let s1 = a.blake3_keyed(&key, b"payload");
    let s2 = a.blake3_keyed(&key, b"payload");
    assert_eq!(s1, s2);
}

#[test]
fn blake3_keyed_distinct_from_unkeyed() {
    let a = adapter();
    let key = [0x99u8; 32];
    let data = b"some data";
    let unkeyed = a.blake3_hash(data);
    let keyed = a.blake3_keyed(&key, data);
    assert_ne!(unkeyed.as_bytes(), keyed.as_bytes());
}

#[test]
fn blake3_keyed_different_keys_differ() {
    let a = adapter();
    let k1 = [0x11u8; 32];
    let k2 = [0x22u8; 32];
    let data = b"same data";
    let s1 = a.blake3_keyed(&k1, data);
    let s2 = a.blake3_keyed(&k2, data);
    assert_ne!(s1, s2);
}

// ---------------------------------------------------------------------------
// Argon2id
// ---------------------------------------------------------------------------

#[test]
fn argon2id_derive_deterministic() {
    let a = adapter();
    let params = Argon2idParams::try_new(65_536, 3, 1, [0xABu8; 16]).expect("valid params");
    let pass = b"correct horse battery staple";

    let k1 = a.argon2id_derive(pass, params.salt(), &params).expect("derive ok");
    let k2 = a.argon2id_derive(pass, params.salt(), &params).expect("derive ok");
    assert_eq!(k1, k2, "same inputs must yield same key");
}

#[test]
fn argon2id_derive_different_salts_differ() {
    let a = adapter();
    let p1 = Argon2idParams::try_new(65_536, 3, 1, [0x01u8; 16]).expect("valid");
    let p2 = Argon2idParams::try_new(65_536, 3, 1, [0x02u8; 16]).expect("valid");
    let pass = b"same password";

    let k1 = a.argon2id_derive(pass, p1.salt(), &p1).expect("ok");
    let k2 = a.argon2id_derive(pass, p2.salt(), &p2).expect("ok");
    assert_ne!(k1, k2, "different salts must yield different keys");
}

#[test]
fn argon2id_params_floor_enforced_by_constructor() {
    // m_cost below floor
    assert!(Argon2idParams::try_new(32_768, 3, 1, [0u8; 16]).is_err());
    // t_cost below floor
    assert!(Argon2idParams::try_new(65_536, 2, 1, [0u8; 16]).is_err());
    // p_cost = 0
    assert!(Argon2idParams::try_new(65_536, 3, 0, [0u8; 16]).is_err());
    // exact floor succeeds
    assert!(Argon2idParams::try_new(65_536, 3, 1, [0u8; 16]).is_ok());
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

#[test]
fn ed25519_sign_verify_round_trip() {
    let a = adapter();
    let (sk, pk) = a.ed25519_keypair();
    let msg = b"approve this reveal";
    let sig = a.ed25519_sign(&sk, msg);
    a.ed25519_verify(&pk, msg, &sig).expect("verify ok");
}

#[test]
fn ed25519_tampered_signature_rejected() {
    let a = adapter();
    let (sk, pk) = a.ed25519_keypair();
    let msg = b"important message";
    let mut sig = a.ed25519_sign(&sk, msg);
    sig[0] ^= 0xFF;
    let err = a.ed25519_verify(&pk, msg, &sig);
    assert!(err.is_err(), "tampered signature must be rejected");
}

#[test]
fn ed25519_wrong_public_key_rejected() {
    let a = adapter();
    let (sk, _pk) = a.ed25519_keypair();
    let (_sk2, pk2) = a.ed25519_keypair();
    let msg = b"cross-key test";
    let sig = a.ed25519_sign(&sk, msg);
    let err = a.ed25519_verify(&pk2, msg, &sig);
    assert!(err.is_err(), "wrong public key must reject signature");
}

// ---------------------------------------------------------------------------
// X25519 ECIES
// ---------------------------------------------------------------------------

#[test]
fn ecies_encrypt_decrypt_round_trip() {
    let a = adapter();
    let (sk, pk) = a.x25519_keypair();
    let plaintext = b"oob-challenge inner payload";
    let aad = b"challenge-id-abc123";

    let envelope = a.x25519_ecies_encrypt(&pk, plaintext, aad).expect("encrypt ok");
    let recovered = a.x25519_ecies_decrypt(&sk, &envelope, aad).expect("decrypt ok");
    assert_eq!(recovered, plaintext);
}

#[test]
fn ecies_wrong_aad_rejected() {
    let a = adapter();
    let (sk, pk) = a.x25519_keypair();
    let plaintext = b"secret payload";
    let aad = b"correct-challenge-id";

    let envelope = a.x25519_ecies_encrypt(&pk, plaintext, aad).expect("ok");
    let err = a.x25519_ecies_decrypt(&sk, &envelope, b"wrong-aad");
    assert!(err.is_err(), "wrong AAD must fail ECIES decryption");
}

#[test]
fn ecies_wrong_private_key_rejected() {
    let a = adapter();
    let (_sk, pk) = a.x25519_keypair();
    let (sk2, _pk2) = a.x25519_keypair();
    let plaintext = b"payload";
    let aad = b"aad";

    let envelope = a.x25519_ecies_encrypt(&pk, plaintext, aad).expect("ok");
    let err = a.x25519_ecies_decrypt(&sk2, &envelope, aad);
    assert!(err.is_err(), "wrong private key must fail ECIES decryption");
}

#[test]
fn ecies_ephemeral_key_is_unique_per_call() {
    let a = adapter();
    let (_sk, pk) = a.x25519_keypair();
    let plaintext = b"data";
    let aad = b"aad";

    let env1 = a.x25519_ecies_encrypt(&pk, plaintext, aad).expect("ok");
    let env2 = a.x25519_ecies_encrypt(&pk, plaintext, aad).expect("ok");
    assert_ne!(
        env1.ephemeral_pubkey, env2.ephemeral_pubkey,
        "ephemeral keys must be unique per encryption call"
    );
}

// ---------------------------------------------------------------------------
// age
// ---------------------------------------------------------------------------

fn make_age_identity_pair() -> (AgeRecipient, AgeIdentity) {
    // Generate a real age X25519 identity.
    let id = age::x25519::Identity::generate();
    let recipient_str = id.to_public().to_string();
    // to_string() returns SecretString; expose_secret() gives &str.
    let identity_str = id.to_string().expose_secret().to_owned();
    (AgeRecipient(recipient_str), AgeIdentity(identity_str))
}

#[test]
fn age_round_trip_single_recipient() {
    let a = adapter();
    let (recipient, identity) = make_age_identity_pair();
    let plaintext = b"backup payload";

    let ct = a.age_encrypt(&[recipient], plaintext).expect("encrypt ok");
    let pt = a.age_decrypt(&identity, &ct).expect("decrypt ok");
    assert_eq!(pt, plaintext);
}

#[test]
fn age_round_trip_two_recipients() {
    let a = adapter();
    let (r1, id1) = make_age_identity_pair();
    let (r2, id2) = make_age_identity_pair();
    let plaintext = b"multi-recipient backup";

    let ct = a.age_encrypt(&[r1, r2], plaintext).expect("encrypt ok");

    let pt1 = a.age_decrypt(&id1, &ct).expect("decrypt with id1 ok");
    let pt2 = a.age_decrypt(&id2, &ct).expect("decrypt with id2 ok");
    assert_eq!(pt1, plaintext);
    assert_eq!(pt2, plaintext);
}

#[test]
fn age_wrong_identity_rejected() {
    let a = adapter();
    let (recipient, _identity) = make_age_identity_pair();
    let (_r2, wrong_identity) = make_age_identity_pair();
    let plaintext = b"secret";

    let ct = a.age_encrypt(&[recipient], plaintext).expect("ok");
    let err = a.age_decrypt(&wrong_identity, &ct);
    assert!(err.is_err(), "wrong identity must fail age decryption");
}

// ---------------------------------------------------------------------------
// Proptest: AEAD encrypt/decrypt roundtrip for arbitrary plaintext
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_aead_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        aad_bytes in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let a = adapter();
        let key = a.random_bytes_32();
        let nonce = a.random_bytes_24();

        let ct = a.aead_encrypt(&key, &nonce, &plaintext, &aad_bytes)
            .expect("proptest encrypt ok");
        let pt = a.aead_decrypt(&key, &nonce, &ct, &aad_bytes)
            .expect("proptest decrypt ok");
        prop_assert_eq!(pt, plaintext);
    }
}
