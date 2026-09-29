#![forbid(unsafe_code)]

pub mod tls;

use base32::Alphabet;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::Ipv6Addr;

/// Overlay ULA /16 prefix (RFC 4193 local-use). Host bits carry identity (address == identity).
pub const OVERLAY_PREFIX: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);

/// A node's cryptographic identity: the ed25519 signing key.
///
/// The node's public key is the anchor of everything: `NodeId`, overlay IPv6,
/// and the self-signed TLS root (see `tls`).
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut csprng = rand::thread_rng();
        let signing = SigningKey::generate(&mut csprng);
        Self { signing }
    }

    pub fn from_signing(signing: SigningKey) -> Self {
        Self { signing }
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self::from_signing(SigningKey::from_bytes(secret))
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// 32-byte identifier derived from the public key.
    pub fn node_id(&self) -> NodeId {
        let digest = Sha256::digest(self.verifying_key().as_bytes());
        NodeId(digest.into())
    }

    /// Overlay IPv6: `fd00::/16` + 14 bytes of SHA-256(pubkey).
    pub fn overlay_ipv6(&self) -> Ipv6Addr {
        let digest = Sha256::digest(self.verifying_key().as_bytes());
        let mut octets = [0u8; 16];
        octets[0] = 0xfd;
        octets[1] = 0x00;
        octets[2..].copy_from_slice(&digest[..14]);
        Ipv6Addr::from(octets)
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.signing.as_bytes()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        *self.secret_bytes()
    }
}

/// 32-byte node identifier (SHA-256 of ed25519 public key).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub const LEN: usize = 32;

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_base32(&self) -> String {
        base32::encode(Alphabet::Rfc4648 { padding: false }, &self.0)
    }

    pub fn short(&self) -> String {
        let mut s = self.to_base32();
        s.truncate(12);
        s
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short())
    }
}

pub mod prelude {
    pub use super::{Identity, NodeId, OVERLAY_PREFIX};
}
