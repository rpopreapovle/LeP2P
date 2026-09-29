//! Single-port QUIC transport (tokio + quinn) with an HTTP/3 JSON control plane.
//!
//! One UDP socket serves everything: QUIC handshake, the HTTP/3 control plane,
//! NAT binding reflection, and (in M2) raw bidi streams for tunnels.

#![forbid(unsafe_code)]

pub mod router;

use lep2p_core::{
    Capabilities, NodeInfo, SCHEMA_VERSION, ALPN_CONTROL,
};
use lep2p_e2ee::KeyBundle;
use lep2p_identity::{tls, Identity, NodeId};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

pub use router::{ControlError, Endpoint, EndpointResult, Router};

/// Context passed to an endpoint handler for one call.
#[derive(Clone)]
pub struct CallCtx {
    /// The remote address as observed on the incoming datagram (NAT reflection).
    pub observed: SocketAddr,
    /// Whether we are the initiator or the receiver of this connection.
    pub is_initiator: bool,
    /// Our own identity (server answering the call).
    pub identity: Arc<Identity>,
    pub capabilities: Capabilities,
    /// The control connection this call arrived on (server side); lets a peer
    /// register itself in the peer table so it can act as rendezvous/target.
    pub conn: Option<quinn::Connection>,
    /// Authenticated identity of the caller, extracted from its TLS client
    /// certificate during the handshake. Unlike self-reported ids in request
    /// bodies, this value cannot be spoofed.
    pub peer_node_id: Option<NodeId>,
}

impl CallCtx {
    pub fn node_info(&self) -> NodeInfo {
        NodeInfo {
            node_id: self.identity.node_id().to_base32(),
            overlay_ipv6: self.identity.overlay_ipv6().to_string(),
            public_addr: Some(self.observed),
            capabilities: self.capabilities.clone(),
        }
    }
}

/// One lazy HTTP/3 client per control connection (protocol must be set up once).
struct H3Client {
    _ctrl: h3::client::Connection<h3_quinn::Connection, bytes::Bytes>,
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
}

/// A live control connection to a peer.
#[derive(Clone)]
pub struct Peer {
    /// Underlying QUIC connection (usable for raw bidi streams in M2).
    pub conn: quinn::Connection,
    pub node_id: NodeId,
    pub observed: SocketAddr,
    /// Verified E2EE key bundle published by this peer (if it announced one).
    key_bundle: Arc<std::sync::RwLock<Option<KeyBundle>>>,
    h3: Arc<tokio::sync::Mutex<Option<H3Client>>>,
}

impl Peer {
    pub fn new(conn: quinn::Connection, node_id: NodeId, observed: SocketAddr) -> Self {
        Self {
            conn,
            node_id,
            observed,
            key_bundle: Arc::new(std::sync::RwLock::new(None)),
            h3: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// The peer's verified E2EE key bundle, if it published one.
    pub fn key_bundle(&self) -> Option<KeyBundle> {
        self.key_bundle.read().unwrap().clone()
    }

    /// Attach a verified key bundle for this peer.
    pub fn set_key_bundle(&self, bundle: KeyBundle) {
        *self.key_bundle.write().unwrap() = Some(bundle);
    }

    /// Send one HTTP/3 JSON control request and await the JSON response.
    pub async fn request(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let mut guard = self.h3.lock().await;
        if guard.is_none() {
            let (conn, sender) =
                h3::client::new(h3_quinn::Connection::new(self.conn.clone())).await?;
            *guard = Some(H3Client { _ctrl: conn, sender });
        }
        let client = guard.as_mut().unwrap();

        let uri = http::Uri::builder()
            .scheme("https")
            .authority("lep2p")
            .path_and_query(path)
            .build()?;
        let req = http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        let mut stream = client.sender.send_request(req).await?;
        stream
            .send_data(bytes::Bytes::from(serde_json::to_vec(&body)?))
            .await?;
        stream.finish().await?;
        let _ = stream.recv_response().await?;

        let mut out = Vec::new();
        while let Ok(Some(mut buf)) = stream.recv_data().await {
            use bytes::Buf;
            let d = buf.copy_to_bytes(buf.remaining());
            out.extend_from_slice(&d);
        }
        Ok(serde_json::from_slice(&out)?)
    }
}

/// A shared registry mapping known NodeIds to their live control connections /
/// observed addresses. Used by NAT (rendezvous for punching) and DHT (routing).
#[derive(Clone, Default)]
pub struct PeerTable {
    inner: Arc<std::sync::RwLock<HashMap<NodeId, Peer>>>,
}

impl PeerTable {
    pub fn insert(&self, peer: Peer) {
        self.inner.write().unwrap().insert(peer.node_id, peer);
    }

    pub fn remove(&self, node_id: &NodeId) {
        self.inner.write().unwrap().remove(node_id);
    }

    pub fn get(&self, node_id: &NodeId) -> Option<Peer> {
        self.inner.read().unwrap().get(node_id).cloned()
    }

    /// Observed socket of a peer, if it is tracked.
    pub fn observed(&self, node_id: &NodeId) -> Option<SocketAddr> {
        self.get(node_id).map(|p| p.observed)
    }

    pub fn all(&self) -> Vec<Peer> {
        self.inner.read().unwrap().values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The transport node: a single QUIC endpoint that both listens and connects.
pub struct NodeTransport {
    identity: Arc<Identity>,
    capability: Capabilities,
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
    publish: SocketAddr,
    /// Obfuscation key routing for all datagrams (wire obfuscation of QUIC).
    obfs: Option<Arc<lep2p_obfs::ObKeyStore>>,
}

impl NodeTransport {
    /// Bind a UDP socket (one port), server rustls config from identity, endpoint.
    pub async fn bind(
        identity: Identity,
        bind_addr: SocketAddr,
        publish_addr: SocketAddr,
        capabilities: Capabilities,
    ) -> anyhow::Result<Self> {
        Self::bind_inner(identity, bind_addr, publish_addr, capabilities, true).await
    }

    /// Like `bind`, but with QUIC-obfuscation disabled (default on when using `bind`).
    pub async fn bind_plain(
        identity: Identity,
        bind_addr: SocketAddr,
        publish_addr: SocketAddr,
        capabilities: Capabilities,
    ) -> anyhow::Result<Self> {
        Self::bind_inner(identity, bind_addr, publish_addr, capabilities, false).await
    }

    async fn bind_inner(
        identity: Identity,
        bind_addr: SocketAddr,
        publish_addr: SocketAddr,
        capabilities: Capabilities,
        obfs: bool,
    ) -> anyhow::Result<Self> {
        let identity = Arc::new(identity);
        let server_tls = tls::build_server_tls(&identity)?;
        let mut scrypto = tls::server_config(&server_tls)?;
        scrypto.alpn_protocols = vec![ALPN_CONTROL.to_vec()];

        let quinn_server_cfg =
            quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(scrypto)?));
        let runtime = quinn::TokioRuntime;

        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        let local_addr = socket.local_addr()?;

        let (endpoint, obfs) = if obfs {
            let keys = Arc::new(lep2p_obfs::ObKeyStore::new(lep2p_obfs::obfs_key(&identity.node_id())));
            let tokio_sock = tokio::net::UdpSocket::from_std(socket)?;
            let obfs_sock: Arc<dyn quinn::AsyncUdpSocket> =
                Arc::new(lep2p_obfs::ObfsSocket::new(tokio_sock, keys.clone()));
            (
                quinn::Endpoint::new_with_abstract_socket(
                    quinn::EndpointConfig::default(),
                    Some(quinn_server_cfg),
                    obfs_sock,
                    Arc::new(runtime),
                )?,
                Some(keys),
            )
        } else {
            (
                quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(quinn_server_cfg),
                    socket,
                    Arc::new(runtime),
                )?,
                None,
            )
        };

        Ok(Self {
            identity,
            capability: capabilities,
            endpoint,
            local_addr,
            publish: publish_addr,
            obfs,
        })
    }

    pub fn identity(&self) -> Arc<Identity> {
        self.identity.clone()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The address advertised to peers for bootstrapping / hole punching.
    pub fn publish_addr(&self) -> SocketAddr {
        self.publish
    }

    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    /// Open a control (HTTP/3) connection to a peer, verifying its NodeId via TLS.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        expected_peer: NodeId,
    ) -> anyhow::Result<Peer> {
        let own_tls = tls::build_server_tls(&self.identity)?;
        let mut cctls = tls::client_config(expected_peer, &own_tls)?;
        cctls.alpn_protocols = vec![ALPN_CONTROL.to_vec()];
        let cc = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(cctls)?,
        ));

        // Register the peer's obfuscation key for this socket before talking.
        if let Some(keys) = &self.obfs {
            keys.set_peer(addr, lep2p_obfs::obfs_key(&expected_peer));
        }

        let connecting = self.endpoint.connect_with(cc, addr, "lep2p")?;
        let conn = connecting.await?;
        let observed = conn.remote_address();
        Ok(Peer::new(conn, expected_peer, observed))
    }

    /// Serve the control plane forever: accept QUIC conns, speak HTTP/3, route JSON.
    pub async fn serve_control(self: Arc<Self>, router: Arc<Router>) -> anyhow::Result<()> {
        loop {
            let incoming = match self.endpoint.accept().await {
                Some(i) => i,
                None => return Ok(()),
            };
            let me = self.clone();
            let router = router.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!("connection failed: {e}");
                        return;
                    }
                };
                if let Err(e) = me.serve_h3_conn(conn, router).await {
                    tracing::debug!("control error: {e}");
                }
            });
        }
    }

    async fn serve_h3_conn(
        &self,
        conn: quinn::Connection,
        router: Arc<Router>,
    ) -> anyhow::Result<()> {
            let observed = conn.remote_address();
            let peer_node_id = peer_cert_node_id(&conn);
            let mut server = h3::server::Connection::new(h3_quinn::Connection::new(conn.clone())).await?;
        loop {
            let req = match server.accept().await? {
                Some(r) => r,
                None => break,
            };
            let (request, mut stream) = req;
            let router = router.clone();
            let ctx = CallCtx {
                observed,
                is_initiator: false,
                identity: self.identity.clone(),
                capabilities: self.capability.clone(),
                conn: Some(conn.clone()),
                peer_node_id,
            };
            tokio::spawn(async move {
                let path = request.uri().path().to_string();

                let mut body = Vec::new();
                while let Ok(Some(mut buf)) = stream.recv_data().await {
                    use bytes::Buf;
                    let d = buf.copy_to_bytes(buf.remaining());
                    body.extend_from_slice(&d);
                    if body.len() >= (1 << 20) {
                        break;
                    }
                }
                let body: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::json!({}));

                let (status, payload) = match router.route(&path) {
                    Some(ep) => match ep.call(&ctx, body).await {
                        Ok(v) => (200, v),
                        Err(e) => {
                            (e.code(), serde_json::json!({"v": SCHEMA_VERSION, "ok": false, "error": e.to_string()}))
                        }
                    },
                    None => (
                        404,
                        serde_json::json!({"v": SCHEMA_VERSION, "ok": false, "error": "not found"}),
                    ),
                };

                let resp = http::Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(())
                    .unwrap();
                if stream.send_response(resp).await.is_err() {
                    return;
                }
                let bytes = serde_json::to_vec(&payload).unwrap_or_default();
                if stream.send_data(bytes::Bytes::from(bytes)).await.is_err() {
                    return;
                }
                let _ = stream.finish().await;
            });
        }
        Ok(())
    }
}

/// Extract the authenticated peer `NodeId` from the TLS client certificate
/// presented during the handshake (mutual TLS).
fn peer_cert_node_id(conn: &quinn::Connection) -> Option<NodeId> {
    let certs = conn
        .peer_identity()?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    tls::cert_node_id(certs.first()?)
}
