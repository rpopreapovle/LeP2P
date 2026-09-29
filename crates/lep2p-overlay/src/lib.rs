//! TUN overlay: IP packets over the LeP2P data plane.
//!
//! Kernel packets enter a TUN device, are routed by destination overlay IPv6
//! address to a peer's data-plane stream, and packets received from peers are
//! written back into the TUN device. The overlay addressing is `address ==
//! identity`, so routes are keyed by `fd00::/16` addresses derived from peer
//! `NodeId`s.

#![forbid(unsafe_code)]

mod linux;
mod memory;
mod node;

pub use lep2p_core::overlay_for;
pub use linux::{LinuxRouteHooks, LinuxTun, LinuxTunReader, LinuxTunWriter};
pub use memory::{MemoryTun, MemoryTunReader, MemoryTunWriter};
pub use node::{OverlayNode, PeerHello, PEER_HELLO_VERSION, RELAY_FRAME_VERSION};

use async_trait::async_trait;
use std::io;
use std::net::Ipv6Addr;

/// Reading half of a packet device (TUN).
#[async_trait]
pub trait TunRead: Send + 'static {
    /// Read one IP packet from the device.
    async fn read_packet(&mut self) -> io::Result<Vec<u8>>;
}

/// Writing half of a packet device (TUN).
#[async_trait]
pub trait TunWrite: Send + Sync + 'static {
    /// Write one IP packet to the device.
    async fn write_packet(&self, packet: &[u8]) -> io::Result<()>;
}

/// Callbacks for installing and removing OS routes for overlay peers.
///
/// [`OverlayNode`] invokes these when a peer route appears (direct or relayed
/// attachment) and disappears (tunnel ended), so the host kernel knows which
/// overlay addresses to send through the TUN device.
pub trait RouteHooks: Send + Sync + 'static {
    /// A peer overlay address became reachable through the tunnel.
    fn route_added(&self, peer: Ipv6Addr);
    /// A peer overlay address is no longer reachable.
    fn route_removed(&self, peer: Ipv6Addr);
}

/// Destination IPv6 address of a packet, if it is IPv6.
pub fn packet_dst_ipv6(packet: &[u8]) -> Option<Ipv6Addr> {
    if packet.first().map(|b| b >> 4) != Some(6) || packet.len() < 40 {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&packet[24..40]);
    Some(Ipv6Addr::from(octets))
}

/// Build a minimal IPv6 packet (tests and diagnostics).
pub fn build_ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 40 + payload.len()];
    packet[0] = 0x60; // version 6
    packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    packet[6] = 59; // no next header
    packet[7] = 64; // hop limit
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());
    packet[40..].copy_from_slice(payload);
    packet
}
