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
pub use linux::{LinuxTun, LinuxTunReader, LinuxTunWriter};
pub use memory::{MemoryTun, MemoryTunReader, MemoryTunWriter};
pub use node::{OverlayNode, PeerHello, PEER_HELLO_VERSION};

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
