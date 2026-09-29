//! Mesh node: routes packets between the TUN device and peer data streams.

use crate::{overlay_for, packet_dst_ipv6, TunRead, TunWrite};
use lep2p_core::parse_node_id;
use lep2p_e2ee::{self, KeyBundle};
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
/// Version of the relay control frames.
pub const RELAY_FRAME_VERSION: u32 = 1;

/// First frame exchanged on a new direct overlay stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHello {
    pub v: u32,
    pub node_id: String,
    pub overlay_ipv6: String,
}

/// Control frames for relayed tunnels (first frame on a new stream).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayFrame {
    /// A -> R: open a tunnel to `to` (with the sender's key bundle).
    Request {
        v: u32,
        to: String,
        from_bundle: KeyBundle,
    },
    /// R -> B: an incoming tunnel from `from` (with the sender's bundle).
    Incoming {
        v: u32,
        from: String,
        from_bundle: KeyBundle,
    },
    /// R -> A: result of the request.
    Established {
        v: u32,
        ok: bool,
        #[serde(default)]
        error: Option<String>,
    },
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
    /// Data connections currently open, keyed by peer id (for relaying).
    data_peers: RwLock<HashMap<NodeId, DataConn>>,
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
            data_peers: RwLock::new(HashMap::new()),
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

    /// Number of data connections currently attached (possible relay targets).
    pub fn data_peer_count(&self) -> usize {
        self.data_peers.read().unwrap().len()
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

    /// Attach a peer directly over an outgoing data connection (we open the
    /// stream and send our hello first).
    pub async fn add_peer(self: &Arc<Self>, conn: DataConn) -> anyhow::Result<NodeId> {
        let mut stream = conn.open_stream().await?;
        send_hello(&mut stream, &self.identity).await?;
        let peer = recv_hello(&mut stream, conn.peer_node_id()).await?;
        self.attach(peer, stream);
        Ok(peer)
    }

    /// Serve a data connection: register it as a possible relay target and
    /// dispatch every accepted stream by its first frame.
    pub fn handle_data(self: &Arc<Self>, conn: DataConn) {
        if let Some(peer) = conn.peer_node_id() {
            self.data_peers.write().unwrap().insert(peer, conn.clone());
        }
        let node = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok(mut stream) = conn.accept_stream().await else {
                    break;
                };
                let Ok(Some(frame)) = stream.recv_packet().await else {
                    break;
                };
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(&frame) else {
                    continue;
                };
                let authed = conn.peer_node_id();
                let node = node.clone();
                tokio::spawn(async move {
                    let result = if value.get("type").is_some() {
                        node.handle_relay_frame(stream, value, authed).await
                    } else {
                        node.handle_hello_frame(stream, value, authed).await
                    };
                    if let Err(e) = result {
                        tracing::debug!("overlay stream rejected: {e}");
                    }
                });
            }
            if let Some(peer) = conn.peer_node_id() {
                node.data_peers.write().unwrap().remove(&peer);
            }
        });
    }

    async fn handle_hello_frame(
        self: &Arc<Self>,
        mut stream: DataStream,
        value: serde_json::Value,
        authenticated: Option<NodeId>,
    ) -> anyhow::Result<()> {
        let hello: PeerHello = serde_json::from_value(value)?;
        let peer = verify_hello(&hello, authenticated)?;
        send_hello(&mut stream, &self.identity).await?;
        self.attach(peer, stream);
        Ok(())
    }

    async fn handle_relay_frame(
        self: &Arc<Self>,
        stream: DataStream,
        value: serde_json::Value,
        authenticated: Option<NodeId>,
    ) -> anyhow::Result<()> {
        let frame: RelayFrame = serde_json::from_value(value)?;
        match frame {
            RelayFrame::Request {
                v,
                to,
                from_bundle,
            } => {
                anyhow::ensure!(v == RELAY_FRAME_VERSION, "unsupported relay version {v}");
                let from = authenticated
                    .ok_or_else(|| anyhow::anyhow!("relay request from unauthenticated peer"))?;
                anyhow::ensure!(
                    from_bundle.verify(&from),
                    "from_bundle does not match the sender"
                );
                self.relay_tunnel(stream, from, to, from_bundle).await
            }
            RelayFrame::Incoming {
                v,
                from,
                from_bundle,
            } => {
                anyhow::ensure!(v == RELAY_FRAME_VERSION, "unsupported relay version {v}");
                let from_id = parse_node_id(&from)
                    .ok_or_else(|| anyhow::anyhow!("bad relay source"))?;
                anyhow::ensure!(
                    from_bundle.verify(&from_id),
                    "from_bundle does not match the source"
                );
                let peer_x = from_bundle
                    .x25519()
                    .ok_or_else(|| anyhow::anyhow!("bad source key bundle"))?;
                self.attach_sealed(from_id, peer_x, stream);
                Ok(())
            }
            RelayFrame::Established { .. } => {
                anyhow::bail!("unexpected relay response frame")
            }
        }
    }

    /// Attach a peer through a relay: packets are sealed end-to-end with
    /// `lep2p-e2ee`, so the relay only forwards opaque blobs.
    pub async fn add_relayed_peer(
        self: &Arc<Self>,
        relay: DataConn,
        peer: NodeId,
        peer_bundle: KeyBundle,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            peer_bundle.verify(&peer),
            "peer key bundle failed verification"
        );
        let peer_x = peer_bundle
            .x25519()
            .ok_or_else(|| anyhow::anyhow!("invalid peer key bundle"))?;

        let mut stream = relay.open_stream().await?;
        let request = serde_json::to_vec(&RelayFrame::Request {
            v: RELAY_FRAME_VERSION,
            to: peer.to_base32(),
            from_bundle: KeyBundle::create(&self.identity),
        })?;
        stream.send_packet(&request).await?;
        let Some(frame) = stream.recv_packet().await? else {
            anyhow::bail!("relay closed the stream");
        };
        match serde_json::from_slice::<RelayFrame>(&frame)? {
            RelayFrame::Established { ok: true, .. } => {}
            RelayFrame::Established { ok: false, error, .. } => {
                anyhow::bail!("relay refused: {}", error.unwrap_or_default())
            }
            _ => anyhow::bail!("unexpected relay response"),
        }

        self.attach_sealed(peer, peer_x, stream);
        Ok(())
    }

    /// Relay side: connect an initiator's stream to the target's stream and
    /// blindly forward sealed blobs between them.
    async fn relay_tunnel(
        self: &Arc<Self>,
        mut from_stream: DataStream,
        from: NodeId,
        to: String,
        from_bundle: KeyBundle,
    ) -> anyhow::Result<()> {
        let target = parse_node_id(&to).ok_or_else(|| anyhow::anyhow!("bad relay target"))?;
        let target_conn = self
            .data_peers
            .read()
            .unwrap()
            .get(&target)
            .cloned();

        let Some(target_conn) = target_conn else {
            let refused = serde_json::to_vec(&RelayFrame::Established {
                v: RELAY_FRAME_VERSION,
                ok: false,
                error: Some("target offline".into()),
            })?;
            from_stream.send_packet(&refused).await?;
            return Ok(());
        };

        let Ok(mut to_stream) = target_conn.open_stream().await else {
            let refused = serde_json::to_vec(&RelayFrame::Established {
                v: RELAY_FRAME_VERSION,
                ok: false,
                error: Some("target unreachable".into()),
            })?;
            from_stream.send_packet(&refused).await?;
            return Ok(());
        };

        let incoming = serde_json::to_vec(&RelayFrame::Incoming {
            v: RELAY_FRAME_VERSION,
            from: from.to_base32(),
            from_bundle,
        })?;
        to_stream.send_packet(&incoming).await?;
        let established = serde_json::to_vec(&RelayFrame::Established {
            v: RELAY_FRAME_VERSION,
            ok: true,
            error: None,
        })?;
        from_stream.send_packet(&established).await?;

        let (mut a_send, mut a_recv) = from_stream.split();
        let (mut b_send, mut b_recv) = to_stream.split();
        tokio::spawn(async move {
            while let Ok(Some(blob)) = a_recv.recv_packet().await {
                if b_send.send_packet(&blob).await.is_err() {
                    break;
                }
            }
            let _ = b_send.finish();
        });
        tokio::spawn(async move {
            while let Ok(Some(blob)) = b_recv.recv_packet().await {
                if a_send.send_packet(&blob).await.is_err() {
                    break;
                }
            }
            let _ = a_send.finish();
        });
        Ok(())
    }

    /// Attach a peer whose packets arrive sealed (relayed tunnel).
    fn attach_sealed(self: &Arc<Self>, peer: NodeId, peer_x: [u8; 32], stream: DataStream) {
        let peer_ip = overlay_for(&peer);
        let (mut send, mut recv) = stream.split();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
        let route_id = self.next_route_id.fetch_add(1, Ordering::Relaxed);
        self.routes
            .write()
            .unwrap()
            .insert(peer_ip, Route { id: route_id, tx });

        // TUN -> seal -> stream.
        let out_identity = self.identity.clone();
        let out_aad = lep2p_e2ee::context_aad(&self.identity.node_id(), &peer);
        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                let blob =
                    lep2p_e2ee::seal_authenticated(&out_identity, &peer_x, &out_aad, &packet);
                if send.send_packet(&blob).await.is_err() {
                    break;
                }
            }
            let _ = send.finish();
        });

        // stream -> open -> TUN; remove the route when the tunnel ends.
        let writer = self.writer.clone();
        let in_identity = self.identity.clone();
        let in_aad = lep2p_e2ee::context_aad(&peer, &self.identity.node_id());
        let node = self.clone();
        tokio::spawn(async move {
            while let Ok(Some(blob)) = recv.recv_packet().await {
                let Ok(packet) =
                    lep2p_e2ee::open_authenticated(&in_identity, &peer_x, &in_aad, &blob)
                else {
                    continue;
                };
                if writer.write_packet(&packet).await.is_err() {
                    break;
                }
            }
            let mut routes = node.routes.write().unwrap();
            if routes.get(&peer_ip).map(|route| route.id) == Some(route_id) {
                routes.remove(&peer_ip);
            }
        });
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

async fn send_hello(stream: &mut DataStream, identity: &Identity) -> anyhow::Result<()> {
    let hello = PeerHello {
        v: PEER_HELLO_VERSION,
        node_id: identity.node_id().to_base32(),
        overlay_ipv6: identity.overlay_ipv6().to_string(),
    };
    stream.send_packet(&serde_json::to_vec(&hello)?).await
}

async fn recv_hello(
    stream: &mut DataStream,
    authenticated: Option<NodeId>,
) -> anyhow::Result<NodeId> {
    let Some(frame) = stream.recv_packet().await? else {
        anyhow::bail!("peer closed during overlay handshake");
    };
    let hello: PeerHello = serde_json::from_slice(&frame)?;
    verify_hello(&hello, authenticated)
}

fn verify_hello(hello: &PeerHello, authenticated: Option<NodeId>) -> anyhow::Result<NodeId> {
    anyhow::ensure!(
        hello.v == PEER_HELLO_VERSION,
        "unsupported overlay hello version {}",
        hello.v
    );
    let peer =
        parse_node_id(&hello.node_id).ok_or_else(|| anyhow::anyhow!("bad peer node_id"))?;
    anyhow::ensure!(
        hello.overlay_ipv6 == overlay_for(&peer).to_string(),
        "overlay address does not match peer identity"
    );
    if let Some(authenticated) = authenticated {
        anyhow::ensure!(
            authenticated == peer,
            "hello identity does not match TLS identity"
        );
    }
    Ok(peer)
}
