//! X25519 key-pair generation helper.

use x25519_dalek::{PublicKey, StaticSecret};
use merkle_ports::{X25519PrivateKey, X25519PublicKey};

use crate::rng::random_32;

/// Generate a fresh X25519 static key pair from `OsRng`.
pub(crate) fn keypair() -> (X25519PrivateKey, X25519PublicKey) {
    let sk_bytes = random_32();
    let sk = StaticSecret::from(sk_bytes);
    let pk = PublicKey::from(&sk);
    (
        X25519PrivateKey(sk.to_bytes()),
        X25519PublicKey(pk.to_bytes()),
    )
}
