//! In-memory TUN replacement for tests.

use crate::{TunRead, TunWrite};
use async_trait::async_trait;
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

/// In-memory TUN device.
///
/// [`MemoryTun::inject`] simulates the OS handing a packet to the tunnel;
/// [`MemoryTun::capture`] / [`MemoryTun::wait_packet`] collect packets the
/// tunnel wrote towards the OS.
#[derive(Clone, Default)]
pub struct MemoryTun {
    inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    inbound_notify: Arc<tokio::sync::Notify>,
    outbound_notify: Arc<tokio::sync::Notify>,
}

impl MemoryTun {
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate the OS sending a packet into the tunnel.
    pub fn inject(&self, packet: Vec<u8>) {
        self.inbound.lock().unwrap().push_back(packet);
        self.inbound_notify.notify_waiters();
    }

    /// Take the next packet the tunnel produced for the OS, if any.
    pub fn capture(&self) -> Option<Vec<u8>> {
        self.outbound.lock().unwrap().pop_front()
    }

    /// Wait up to `timeout` for a packet produced for the OS.
    pub async fn wait_packet(&self, timeout: std::time::Duration) -> Option<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(packet) = self.capture() {
                return Some(packet);
            }
            let notified = self.outbound_notify.notified();
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(deadline) => return self.capture(),
            }
        }
    }

    /// Reader half for an [`crate::OverlayNode`].
    pub fn reader(&self) -> MemoryTunReader {
        MemoryTunReader { tun: self.clone() }
    }

    /// Writer half for an [`crate::OverlayNode`].
    pub fn writer(&self) -> MemoryTunWriter {
        MemoryTunWriter { tun: self.clone() }
    }
}

/// Reader half of a [`MemoryTun`].
pub struct MemoryTunReader {
    tun: MemoryTun,
}

#[async_trait]
impl TunRead for MemoryTunReader {
    async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(packet) = self.tun.inbound.lock().unwrap().pop_front() {
                return Ok(packet);
            }
            self.tun.inbound_notify.notified().await;
        }
    }
}

/// Writer half of a [`MemoryTun`].
pub struct MemoryTunWriter {
    tun: MemoryTun,
}

#[async_trait]
impl TunWrite for MemoryTunWriter {
    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        self.tun
            .outbound
            .lock()
            .unwrap()
            .push_back(packet.to_vec());
        self.tun.outbound_notify.notify_waiters();
        Ok(())
    }
}
