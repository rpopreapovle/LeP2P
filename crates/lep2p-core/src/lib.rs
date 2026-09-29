//! Shared protocol types: NodeInfo, capabilities, wire payloads, schema version.

#![forbid(unsafe_code)]

use lep2p_identity::NodeId;
use serde::{Deserialize, Serialize};
use std::net::{Ipv6Addr, SocketAddr};

/// Current wire/schema version. Bumped on breaking protocol changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Control-plane ALPN used for HTTP/3.
pub const ALPN_CONTROL: &[u8] = b"h3";
/// Data-plane ALPN used for raw bidi tunnelling streams.
pub const ALPN_OVERLAY: &[u8] = b"lep2p-overlay";

/// Overlay IPv6 address derived from a `NodeId` (`fd00::/16` + 14 hash bytes),
/// so `address == identity`.
pub fn overlay_for(node_id: &NodeId) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1] = 0x00;
    octets[2..].copy_from_slice(&node_id.as_bytes()[..14]);
    Ipv6Addr::from(octets)
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capabilities {
    pub schema_version: u32,
    pub nat: NatCapabilities,
    pub dht: bool,
    pub overlay: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatCapabilities {
    pub hole_punch: bool,
    pub relay: bool,
    pub methods: Vec<NatMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NatMethod {
    Reflect,
    HolePunch,
    Relay,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            nat: NatCapabilities {
                hole_punch: true,
                relay: false,
                methods: vec![NatMethod::Reflect, NatMethod::HolePunch],
            },
            dht: true,
            overlay: false,
        }
    }
}

// ---------------------------------------------------------------------------
// NodeInfo
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInfo {
    pub node_id: String,
    pub overlay_ipv6: String,
    /// Publicly observable address (populated after reflect).
    pub public_addr: Option<SocketAddr>,
    pub capabilities: Capabilities,
}

// ---------------------------------------------------------------------------
// Control-plane payloads (HTTP/3 JSON bodies)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    pub v: u32,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PingReq {
    pub v: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PingResp {
    pub v: u32,
    pub node_id: String,
    pub capabilities: Capabilities,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoReq {
    pub v: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResp {
    pub v: u32,
    pub node: NodeInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectReq {
    pub v: u32,
    pub node_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectResp {
    pub v: u32,
    pub node: NodeInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReflectReq {
    pub v: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReflectResp {
    pub v: u32,
    pub observed: SocketAddr,
}

/// Punch request: ask the rendezvous peer to relay a punch toward `target`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PunchReq {
    pub v: u32,
    pub target: String,
}

/// Response to a punch exchange: the observed endpoint of the target plus both
/// sides' punch intent, so both peers can fire QUIC Initials at each other.
#[derive(Debug, Serialize, Deserialize)]
pub struct PunchResp {
    pub v: u32,
    pub target_observed: SocketAddr,
    pub initiator_intent: PunchIntent,
    pub target_intent: PunchIntent,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PunchIntent {
    pub node_id: String,
    pub observed: SocketAddr,
    pub alpn_hint: String,
}

// DHT payloads (see lep2p-dht for routing logic).

#[derive(Debug, Serialize, Deserialize)]
pub struct FindNodeReq {
    pub v: u32,
    pub target_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindNodeResp {
    pub v: u32,
    pub nodes: Vec<NodeInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PutReq {
    pub v: u32,
    pub key: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PutResp {
    pub v: u32,
    pub stored: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetReq {
    pub v: u32,
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetResp {
    pub v: u32,
    pub value: Option<String>,
    pub nodes: Vec<NodeInfo>,
}

// Relay (stub for M1).

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayOfferReq {
    pub v: u32,
    pub target: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayOfferResp {
    pub v: u32,
    pub relay_addr: Option<SocketAddr>,
    pub supported: bool,
}

/// Parse a NodeId from its base32 string representation.
pub fn parse_node_id(s: &str) -> Option<NodeId> {
    let bytes = base32_decode(s)?;
    if bytes.len() != NodeId::LEN {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(NodeId(arr))
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    // RFC4648 no-padding, cross-check round trip to be strict.
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s)
}

pub mod prelude {
    pub use super::{
        parse_node_id, Capabilities, NatCapabilities, NatMethod, NodeInfo, ALPN_CONTROL,
        ALPN_OVERLAY, SCHEMA_VERSION,
    };
}
