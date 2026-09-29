//! End-to-end encryption for LeP2P payloads.
//!
//! Direct QUIC connections are already protected by TLS 1.3 with a pinned
//! self-signed node identity. This crate adds an *application-layer* end-to-end
//! encryption that survives intermediate nodes: any message sealed here can
//! pass through a rendezvous or relay node without that node being able to
//! read (or meaningfully modify) its content.
//!
//! ## Key agreement
//!
//! Each node derives a static X25519 key from its ed25519 identity:
//!
//! - secret scalar: `SHA-512(ed25519_seed)[0..32]` (clamped), the standard
//!   `crypto_sign_ed25519_sk_to_curve25519` construction;
//! - public key: the ed25519 public key mapped to Montgomery form.
//!
//! Peers exchange public keys (they are included in node certificates and can
//! be shared explicitly) and compute the same shared secret via X25519. The
//! raw shared point is then run through HKDF-SHA256 with the domain separation
//! string `lep2p-e2ee-v1`.
//!
//! ## Sealed payloads
//!
//! [`seal`] produces `nonce || AEAD ciphertext` (ChaCha20-Poly1305, 24-byte
//! random nonce, associated data bound to the message context). [`open`]
//! returns an error on any tampering, truncation, or wrong key.

#![forbid(unsafe_code)]

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use lep2p_identity::{Identity, NodeId};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

/// HKDF salt / domain separation for the key schedule.
const HKDF_SALT: &[u8] = b"lep2p-e2ee-v1-kdf";
/// HKDF info for the shared session key.
const HKDF_INFO: &[u8] = b"lep2p-e2ee-v1-session";
/// Nonce length of ChaCha20-Poly1305.
pub const NONCE_LEN: usize = 12;

/// Errors from unsealing or key derivation.
#[derive(Debug, thiserror::Error)]
pub enum E2eeError {
    /// The sealed payload is malformed (too short).
    #[error("malformed sealed payload")]
    Malformed,
    /// Authentication failed: wrong key, tampered ciphertext, or wrong AAD.
    #[error("authentication failed")]
    AuthFailed,
}

/// Derive the node's static X25519 secret from its ed25519 identity.
fn x25519_secret(identity: &Identity) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(identity.secret_bytes());
    let digest = h.finalize();

    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&digest[..32]);
    // Standard X25519 clamping.
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

/// The node's public X25519 key (Montgomery form of the ed25519 public key).
///
/// This is safe to publish; peers need it to derive the shared secret.
pub fn public_key(identity: &Identity) -> [u8; 32] {
    identity.verifying_key().to_montgomery().to_bytes()
}

/// Derive the shared session key between `identity` and a peer's public key.
///
/// Both sides compute the same key: `shared(secret_a, pub_b) == shared(secret_b, pub_a)`.
pub fn shared_key(identity: &Identity, peer_public: &[u8; 32]) -> [u8; 32] {
    let mut secret = x25519_secret(identity);
    let shared = x25519_dalek::x25519(secret, *peer_public);
    secret.zeroize();

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &shared);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// Convenience: shared key using the peer's `NodeId`-derived public key.
///
/// Requires the caller to already know the peer's X25519 public key bytes
/// (see [`public_key`]).
pub fn shared_key_with_peer(identity: &Identity, peer_public: &[u8; 32]) -> [u8; 32] {
    shared_key(identity, peer_public)
}

/// Associated data binding a sealed message to its context (sender/receiver).
///
/// Using both node ids as AAD prevents a ciphertext from being replayed
/// verbatim into a different session between other nodes.
pub fn context_aad(sender: &NodeId, receiver: &NodeId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(b"lep2p-e2ee-v1");
    aad.extend_from_slice(sender.as_bytes());
    aad.extend_from_slice(receiver.as_bytes());
    aad
}

/// Seal `plaintext` under `key` with `aad`, returning `nonce || ciphertext`.
pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("ChaCha20-Poly1305 encryption cannot fail for in-memory buffers");

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Open a payload produced by [`seal`].
pub fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, E2eeError> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err(E2eeError::Malformed);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| E2eeError::AuthFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identities() -> (Identity, Identity, Identity) {
        (
            Identity::from_bytes(&[1u8; 32]),
            Identity::from_bytes(&[2u8; 32]),
            Identity::from_bytes(&[3u8; 32]),
        )
    }

    #[test]
    fn mutual_shared_key_matches() {
        let (a, b, _) = identities();
        let ab = shared_key(&a, &public_key(&b));
        let ba = shared_key(&b, &public_key(&a));
        assert_eq!(ab, ba);
    }

    #[test]
    fn different_peers_different_keys() {
        let (a, b, c) = identities();
        let ab = shared_key(&a, &public_key(&b));
        let ac = shared_key(&a, &public_key(&c));
        assert_ne!(ab, ac);
    }

    #[test]
    fn seal_open_roundtrip() {
        let (a, b, _) = identities();
        let key = shared_key(&a, &public_key(&b));
        let aad = context_aad(&a.node_id(), &b.node_id());

        let msg = b"rendezvous payload that must stay private";
        let sealed = seal(&key, &aad, msg);
        let opened = open(&key, &aad, &sealed).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (a, b, _) = identities();
        let key = shared_key(&a, &public_key(&b));
        let aad = context_aad(&a.node_id(), &b.node_id());

        let mut sealed = seal(&key, &aad, b"hello");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(open(&key, &aad, &sealed), Err(E2eeError::AuthFailed)));
    }

    #[test]
    fn wrong_aad_is_rejected() {
        let (a, b, c) = identities();
        let key = shared_key(&a, &public_key(&b));
        let good = context_aad(&a.node_id(), &b.node_id());
        let bad = context_aad(&a.node_id(), &c.node_id());

        let sealed = seal(&key, &good, b"hello");
        assert!(matches!(open(&key, &bad, &sealed), Err(E2eeError::AuthFailed)));
    }

    #[test]
    fn truncated_payload_is_malformed() {
        let key = [7u8; 32];
        assert!(matches!(open(&key, b"", &[0u8; 20]), Err(E2eeError::Malformed)));
    }
}
