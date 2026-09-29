//! Mesh node: routes packets between the TUN device and peer data streams.

use crate::{overlay_for, packet_dst_ipv6, TunRead, TunWrite};
use lep2p_core::parse_node_id;
use lep2p_identity::{Identity, NodeId};
use lep2p_transport::{DataConn, DataStream};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

/// Version of the overlay peer handshake.
pub const PEER_HELLO_VERSION: u32 = 1;

/// First frame exchanged on a new overlay stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHello {
    pub v: u32,
    pub node_id: String,
    pub overlay_ipv6: String,
}

struct Route {
    id: u64,
    tx: mpsc::Sender<Vec<u8>>,
}

/// A mesh node bridging a TUN device to peer data streams.
///
/// Routes are keyed by peer overlay IPv6 addresses; packets from the TUN whose
/// destination has no route are dropped (logged). Packets from peers are
/// written straight back into the TUN device.
pub struct OverlayNode {
    identity: Arc<Identity>,
    overlay_ipv6: Ipv6Addr,
    routes: RwLock<HashMap<Ipv6Addr, Route>>,
    next_route_id: AtomicU64,
    writer: Arc<dyn TunWrite>,
}

impl OverlayNode {
    /// Start the node, taking ownership of the TUN reader loop.
    pub fn start(
        identity: Arc<Identity>,
        reader: Box<dyn TunRead>,
        writer: Arc<dyn TunWrite>,
    ) -> Arc<Self> {
        let overlay_ipv6 = identity.overlay_ipv6();
        let node = Arc::new(Self {
            identity,
            overlay_ipv6,
            routes: RwLock::new(HashMap::new()),
            next_route_id: AtomicU64::new(1),
            writer,
        });

        let reader_node = node.clone();
        tokio::spawn(async move {
            reader_node.read_loop(reader).await;
        });
        node
    }

    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    pub fn overlay_ipv6(&self) -> Ipv6Addr {
        self.overlay_ipv6
    }

    /// Whether a route to `dst` is currently registered.
    pub fn has_route(&self, dst: &Ipv6Addr) -> bool {
        self.routes.read().unwrap().contains_key(dst)
    }

    /// Number of registered peer routes.
    pub fn route_count(&self) -> usize {
        self.routes.read().unwrap().len()
    }

    async fn read_loop(&self, mut reader: Box<dyn TunRead>) {
        loop {
            match reader.read_packet().await {
                Ok(packet) => self.route_packet(packet).await,
                Err(e) => {
                    tracing::debug!("tun read ended: {e}");
                    return;
                }
            }
        }
    }

    async fn route_packet(&self, packet: Vec<u8>) {
        let Some(dst) = packet_dst_ipv6(&packet) else {
            tracing::debug!("overlay: dropping non-IPv6 packet");
            return;
        };
        let sender = self
            .routes
            .read()
            .unwrap()
            .get(&dst)
            .map(|route| route.tx.clone());
        match sender {
            Some(tx) => {
                if tx.send(packet).await.is_err() {
                    tracing::debug!("overlay: route to {dst} closed");
                }
            }
            None => tracing::debug!("overlay: no route to {dst}"),
        }
    }

    /// Attach a peer over an outgoing data connection (we open the stream).
    pub async fn add_peer(self: &Arc<Self>, conn: DataConn) -> anyhow::Result<NodeId> {
        let mut stream = conn.open_stream().await?;
        let peer = self.exchange_hello(&mut stream, conn.peer_node_id()).await?;
        self.attach(peer, stream);
        Ok(peer)
    }

    /// Attach a peer over an incoming data connection (we accept the stream).
    pub async fn accept_peer(self: &Arc<Self>, conn: DataConn) -> anyhow::Result<NodeId> {
        let mut stream = conn.accept_stream().await?;
        let peer = self.exchange_hello(&mut stream, conn.peer_node_id()).await?;
        self.attach(peer, stream);
        Ok(peer)
    }

    async fn exchange_hello(
        &self,
        stream: &mut DataStream,
        authenticated: Option<NodeId>,
    ) -> anyhow::Result<NodeId> {
        let hello = PeerHello {
            v: PEER_HELLO_VERSION,
            node_id: self.identity.node_id().to_base32(),
            overlay_ipv6: self.identity.overlay_ipv6().to_string(),
        };
        stream
            .send_packet(&serde_json::to_vec(&hello)?)
            .await?;
        let Some(frame) = stream.recv_packet().await? else {
            anyhow::bail!("peer closed during overlay handshake");
        };
        let hello: PeerHello = serde_json::from_slice(&frame)?;
        if hello.v != PEER_HELLO_VERSION {
            anyhow::bail!("unsupported overlay hello version {}", hello.v);
        }
        let peer = parse_node_id(&hello.node_id)
            .ok_or_else(|| anyhow::anyhow!("bad peer node_id"))?;
        if hello.overlay_ipv6 != overlay_for(&peer).to_string() {
            anyhow::bail!("overlay address does not match peer identity");
        }
        if let Some(authenticated) = authenticated {
            if authenticated != peer {
                anyhow::bail!("hello identity does not match TLS identity");
            }
        }
        Ok(peer)
    }

    fn attach(self: &Arc<Self>, peer: NodeId, stream: DataStream) {
        let peer_ip = overlay_for(&peer);
        let (mut send, mut recv) = stream.split();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
        let route_id = self.next_route_id.fetch_add(1, Ordering::Relaxed);
        self.routes
            .write()
            .unwrap()
            .insert(peer_ip, Route { id: route_id, tx });

        // Packets from the peer go into the TUN device.
        let writer = self.writer.clone();
        tokio::spawn(async move {
            while let Ok(Some(packet)) = recv.recv_packet().await {
                if writer.write_packet(&packet).await.is_err() {
                    break;
                }
            }
        });

        // Packets from the TUN go to the peer; remove the route when done.
        let node = self.clone();
        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                if send.send_packet(&packet).await.is_err() {
                    break;
                }
            }
            let _ = send.finish();
            let mut routes = node.routes.write().unwrap();
            if routes.get(&peer_ip).map(|route| route.id) == Some(route_id) {
                routes.remove(&peer_ip);
            }
        });
    }
}
