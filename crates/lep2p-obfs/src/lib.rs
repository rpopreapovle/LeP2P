//! Datagram-level obfuscation for QUIC (like Salamander for hysteria2).
//!
//! Every node derives an obfuscation key from its identity's `NodeId`, and every
//! UDP datagram carrying a QUIC packet is XOR-"whited" against a keyed keystream
//! before hitting the wire, so DPI cannot recognise the QUIC / TLS 1.3 signatures.
//! The wire key for a connection is the *receiver's* node key (the client derives
//! the server's key from the server's `NodeId` it is connecting to).

#![forbid(unsafe_code)]

use lep2p_identity::NodeId;
use quinn::{AsyncUdpSocket, UdpPoller};
use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{ready, Context, Poll};
use tokio::io::Interest;

const NONCE_LEN: usize = 8;
const KDF_DOMAIN: &[u8] = b"lep2p-obfs-v1";

/// Derive a node's obfuscation key from its `NodeId` (cryptographically).
pub fn obfs_key(node_id: &NodeId) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KDF_DOMAIN);
    h.update(node_id.0);
    h.finalize().into()
}

/// Generate one 32-byte keystream block for `block_index` from `key + nonce`.
fn keystream_block(key: &[u8; 32], nonce: &[u8; 8], block_index: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(key);
    h.update(nonce);
    h.update(block_index.to_le_bytes());
    h.finalize().into()
}

/// Obfuscate `plain` into `nonce || cipher`. Length grows by `NONCE_LEN`.
fn obfuscate(key: &[u8; 32], nonce: u64, plain: &[u8]) -> Vec<u8> {
    let nonce_bytes = nonce.to_le_bytes();
    let mut out = Vec::with_capacity(NONCE_LEN + plain.len());
    out.extend_from_slice(&nonce_bytes);
    for (i, &b) in plain.iter().enumerate() {
        let block = keystream_block(key, &nonce_bytes, (i / 32) as u32);
        out.push(b ^ block[i % 32]);
    }
    out
}

/// Remove obfuscation: strips the nonce and un-XORs the rest.
fn deobfuscate(key: &[u8; 32], packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < NONCE_LEN {
        return None;
    }
    let nonce: [u8; 8] = packet[..NONCE_LEN].try_into().ok()?;
    let mut out = Vec::with_capacity(packet.len() - NONCE_LEN);
    for (i, &b) in packet[NONCE_LEN..].iter().enumerate() {
        let block = keystream_block(key, &nonce, (i / 32) as u32);
        out.push(b ^ block[i % 32]);
    }
    Some(out)
}

/// Routes wire obfuscation keys by peer address, falling back to our own node key.
pub struct ObKeyStore {
    own: [u8; 32],
    peer: RwLock<HashMap<SocketAddr, [u8; 32]>>,
}

impl ObKeyStore {
    pub fn new(own: [u8; 32]) -> Self {
        Self {
            own,
            peer: RwLock::new(HashMap::new()),
        }
    }

    /// Register the obfuscation key for a peer we connect to (its node key).
    pub fn set_peer(&self, addr: SocketAddr, key: [u8; 32]) {
        self.peer.write().unwrap().insert(addr, key);
    }

    fn key_for(&self, addr: &SocketAddr) -> [u8; 32] {
        self.peer
            .read()
            .unwrap()
            .get(addr)
            .copied()
            .unwrap_or(self.own)
    }
}

/// An `AsyncUdpSocket` that obfuscates every datagram on send and receive.
pub struct ObfsSocket {
    io: Arc<tokio::net::UdpSocket>,
    keys: Arc<ObKeyStore>,
    nonce: AtomicU64,
    recv_buf: Mutex<Box<[u8]>>,
}

impl std::fmt::Debug for ObfsSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfsSocket").finish()
    }
}

impl ObfsSocket {
    pub fn new(io: tokio::net::UdpSocket, keys: Arc<ObKeyStore>) -> Self {
        Self {
            io: Arc::new(io),
            keys,
            nonce: AtomicU64::new(1),
            recv_buf: Mutex::new(vec![0u8; 65535].into_boxed_slice()),
        }
    }

    pub fn keys(&self) -> Arc<ObKeyStore> {
        self.keys.clone()
    }
}

impl AsyncUdpSocket for ObfsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(WritablePoller {
            io: self.io.clone(),
            fut: Mutex::new(None),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let key = self.keys.key_for(&transmit.destination);
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed);
        let obfs = obfuscate(&key, nonce, transmit.contents);
        match self.io.try_send_to(&obfs, transmit.destination) {
            Ok(n) if n == obfs.len() => Ok(()),
            Ok(_) => Err(io::Error::new(io::ErrorKind::WriteZero, "partial send")),
            Err(e) => Err(e),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut guard = self.recv_buf.lock().unwrap();
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_io(Interest::READABLE, || {
                self.io.try_recv_from(&mut guard[..])
            }) {
                Ok((n, src)) => {
                    if let Some(plain) = deobfuscate(&self.keys.key_for(&src), &guard[..n]) {
                        tracing::debug!("obfs recv {n}B from {src}: decoded");
                        let n = plain.len().min(bufs[0].len());
                        bufs[0][..n].copy_from_slice(&plain[..n]);
                        meta[0] = RecvMeta {
                            addr: src,
                            len: n,
                            stride: n,
                            ecn: None,
                            dst_ip: None,
                        };
                        return Poll::Ready(Ok(1));
                    }
                    tracing::debug!("obfs recv {n}B from {src}: DECODE FAILED, dropped");
                }
                Err(e) => {
                    // Retry: the loop re-polls readiness, re-registering the waker.
                    tracing::trace!("obfs recv try_io error: {e}");
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

type BoxFuture = Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>;

/// Poller notifying when the underlying socket is writable.
struct WritablePoller {
    io: Arc<tokio::net::UdpSocket>,
    fut: Mutex<Option<BoxFuture>>,
}

impl std::fmt::Debug for WritablePoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WritablePoller").finish()
    }
}

impl UdpPoller for WritablePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let mut guard = self.fut.lock().unwrap();
        if guard.is_none() {
            let io = self.io.clone();
            *guard = Some(Box::pin(async move { io.writable().await }));
        }
        let poll = guard.as_mut().unwrap().as_mut().poll(cx);
        if poll.is_ready() {
            *guard = None;
        }
        poll
    }
}

// Keep EcnCodepoint referenced (quinn compat; ecn is None in our socket).
#[allow(dead_code)]
fn _ecn(_: Option<EcnCodepoint>) {}

pub mod prelude {
    pub use super::{ObfsSocket, ObKeyStore, obfs_key};
}
