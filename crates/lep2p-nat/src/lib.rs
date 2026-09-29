//! NAT traversal: binding reflection (our own STUN analog), UDP hole punching,
//! and the relay/TURN pluggable trait (stub in M1).

#![forbid(unsafe_code)]

use async_trait::async_trait;
use lep2p_core::{
    parse_node_id, NatCapabilities, NatMethod, PunchIntent, PunchReq, PunchResp, ReflectReq,
    ReflectResp,
};
use lep2p_e2ee::KeyBundle;
use lep2p_identity::NodeId;
use lep2p_transport::{CallCtx, ControlError, Endpoint, EndpointResult, Peer, PeerTable};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// Reflect endpoint: return the caller's observed external `ip:port`, read from
/// the source of the incoming QUIC datagram (built-in STUN analog on the same port).
pub struct ReflectEndpoint;

#[async_trait]
impl Endpoint for ReflectEndpoint {
    async fn call(&self, ctx: &CallCtx, body: serde_json::Value) -> EndpointResult {
        let _req: ReflectReq = lep2p_transport::router::decode(body)?;
        Ok(json!(ReflectResp {
            v: lep2p_core::SCHEMA_VERSION,
            observed: ctx.observed,
        }))
    }
}

/// Punch endpoint (hosted on a rendezvous peer R): given `target` NodeId, return
/// the target's observed endpoint plus both sides' intents so the initiator and
/// target can fire QUIC Initials at each other's public addresses.
pub struct PunchEndpoint {
    peers: Arc<PeerTable>,
}

impl PunchEndpoint {
    pub fn new(peers: Arc<PeerTable>) -> Self {
        Self { peers }
    }
}

#[async_trait]
impl Endpoint for PunchEndpoint {
    async fn call(&self, ctx: &CallCtx, body: serde_json::Value) -> EndpointResult {
        let req: PunchReq = lep2p_transport::router::decode(body)?;
        let target = parse_node_id(&req.target)
            .ok_or_else(|| ControlError::BadRequest("bad target node_id".into()))?;

        let target_peer = self
            .peers
            .get(&target)
            .ok_or_else(|| ControlError::BadRequest("target not reachable via rendezvous".into()))?;

        let initiator_intent = PunchIntent {
            node_id: ctx.identity.node_id().to_base32(),
            observed: ctx.observed,
            alpn_hint: String::from_utf8_lossy(lep2p_core::ALPN_CONTROL).into_owned(),
        };
        let target_intent = PunchIntent {
            node_id: target_peer.node_id.to_base32(),
            observed: target_peer.observed,
            alpn_hint: String::from_utf8_lossy(lep2p_core::ALPN_CONTROL).into_owned(),
        };

        Ok(json!(PunchResp {
            v: lep2p_core::SCHEMA_VERSION,
            target_observed: target_peer.observed,
            initiator_intent,
            target_intent,
        }))
    }
}

/// Client-side helpers to drive NAT traversal against a rendezvous peer.
pub struct NatClient {
    pub transport: Arc<lep2p_transport::NodeTransport>,
}

impl NatClient {
    /// Ask a rendezvous peer what external `ip:port` this node appears from.
    pub async fn reflect(&self, rendezvous: &Peer) -> anyhow::Result<SocketAddr> {
        let resp = rendezvous
            .request("/v1/nat/reflect", json!(ReflectReq { v: lep2p_core::SCHEMA_VERSION }))
            .await?;
        let resp: ReflectResp = serde_json::from_value(resp)?;
        Ok(resp.observed)
    }

    /// Hole punch toward `target` through `rendezvous`, then connect directly.
    ///
    /// In M1 this returns the direct connection opened after learning the target's
    /// public address from the rendezvous. (Symmetric-NAT both-side firing is M2.)
    pub async fn hole_punch(
        &self,
        rendezvous: &Peer,
        target: NodeId,
    ) -> anyhow::Result<Peer> {
        let resp = rendezvous
            .request(
                "/v1/nat/punch",
                json!(PunchReq {
                    v: lep2p_core::SCHEMA_VERSION,
                    target: target.to_base32(),
                }),
            )
            .await?;
        let resp: PunchResp = serde_json::from_value(resp)?;
        tracing::debug!("punch target observed: {}", resp.target_observed);
        self.transport.connect(resp.target_observed, target).await
    }
}

/// Pluggable relay (TURN-analog). Stub in M1: returns unsupported.
pub trait Relayer: Send + Sync {
    fn supports(&self) -> bool;

    /// Return a proxy address a peer can tunnel through to `target`.
    fn offer(&self, target: &NodeId) -> Option<SocketAddr>;
}

/// Relay endpoint backed by a `Relayer` (stub returns `supported: false`).
pub struct RelayEndpoint {
    relayer: Arc<dyn Relayer>,
}

impl RelayEndpoint {
    pub fn new(relayer: Arc<dyn Relayer>) -> Self {
        Self { relayer }
    }
}

/// A `Relayer` that never provides relays (the M1 default).
pub struct NoRelay;

impl Relayer for NoRelay {
    fn supports(&self) -> bool {
        false
    }
    fn offer(&self, _target: &NodeId) -> Option<SocketAddr> {
        None
    }
}

#[async_trait]
impl Endpoint for RelayEndpoint {
    async fn call(&self, ctx: &CallCtx, body: serde_json::Value) -> EndpointResult {
        let target = body
            .get("target")
            .and_then(|v| v.as_str())
            .and_then(parse_node_id)
            .ok_or_else(|| ControlError::BadRequest("bad target".into()))?;
        let relay_addr = self.relayer.offer(&target);
        Ok(json!({
            "v": lep2p_core::SCHEMA_VERSION,
            "relay_addr": relay_addr,
            "supported": self.relayer.supports(),
            "observed": ctx.observed,
        }))
    }
}

/// Default NAT capabilities advertised by a node (hole punch on, relay off).
pub fn default_nat_caps() -> NatCapabilities {
    NatCapabilities {
        hole_punch: true,
        relay: false,
        methods: vec![NatMethod::Reflect, NatMethod::HolePunch],
    }
}

// ---------------------------------------------------------------------------
// Rendezvous registration, key distribution, and sealed-blob relay
// ---------------------------------------------------------------------------

/// `/v1/hello` handler: registers the mutually authenticated caller's
/// `node_id` -> observed address and, optionally, its verified E2EE bundle.
pub struct HelloEndpoint {
    peers: Arc<PeerTable>,
}

impl HelloEndpoint {
    pub fn new(peers: Arc<PeerTable>) -> Self {
        Self { peers }
    }
}

#[derive(serde::Deserialize)]
struct HelloReq {
    #[allow(dead_code)]
    v: u32,
    node_id: String,
    #[serde(default)]
    key_bundle: Option<KeyBundle>,
}

#[async_trait]
impl Endpoint for HelloEndpoint {
    async fn call(&self, ctx: &CallCtx, body: serde_json::Value) -> EndpointResult {
        let req: HelloReq = lep2p_transport::router::decode(body)?;
        let node_id = parse_node_id(&req.node_id)
            .ok_or_else(|| ControlError::BadRequest("bad node_id".into()))?;

        // Bind the claimed id to the TLS-authenticated identity.
        if let Some(authed) = ctx.peer_node_id {
            if authed != node_id {
                return Err(ControlError::BadRequest(
                    "node_id does not match TLS identity".into(),
                ));
            }
        }

        if let Some(conn) = &ctx.conn {
            let peer = Peer::new(conn.clone(), node_id, ctx.observed);
            if let Some(bundle) = &req.key_bundle {
                if bundle.verify(&node_id) {
                    peer.set_key_bundle(bundle.clone());
                } else {
                    tracing::warn!(
                        "hello: rejected invalid key bundle from {}",
                        node_id.short()
                    );
                }
            }
            self.peers.insert(peer);
        }

        use lep2p_transport::router::ok;
        ok(json!({ "v": lep2p_core::SCHEMA_VERSION, "ok": true }))
    }
}

/// `/v1/node/keys`: returns the verified E2EE key bundle of a known peer.
pub struct NodeKeysEndpoint {
    peers: Arc<PeerTable>,
}

impl NodeKeysEndpoint {
    pub fn new(peers: Arc<PeerTable>) -> Self {
        Self { peers }
    }
}

#[derive(serde::Deserialize)]
struct NodeKeysReq {
    #[allow(dead_code)]
    v: u32,
    node_id: String,
}

#[async_trait]
impl Endpoint for NodeKeysEndpoint {
    async fn call(&self, _ctx: &CallCtx, body: serde_json::Value) -> EndpointResult {
        let req: NodeKeysReq = lep2p_transport::router::decode(body)?;
        let node_id = parse_node_id(&req.node_id)
            .ok_or_else(|| ControlError::BadRequest("bad node_id".into()))?;
        let bundle = self.peers.get(&node_id).and_then(|p| p.key_bundle());

        use lep2p_transport::router::ok;
        ok(json!({ "v": lep2p_core::SCHEMA_VERSION, "key_bundle": bundle }))
    }
}

/// A sealed blob queued in a relay mailbox.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayedBlob {
    /// Sender's `NodeId` in base32.
    pub from: String,
    /// Sender's verified E2EE key bundle.
    pub from_bundle: KeyBundle,
    /// Sealed payload (`lep2p_e2ee::seal` output).
    pub blob: Vec<u8>,
}

/// Per-target mailboxes of sealed blobs awaiting pickup.
#[derive(Clone, Default)]
pub struct RelayQueues {
    inner: Arc<Mutex<HashMap<NodeId, VecDeque<RelayedBlob>>>>,
}

impl RelayQueues {
    pub fn push(&self, to: NodeId, blob: RelayedBlob) {
        self.inner
            .lock()
            .unwrap()
            .entry(to)
            .or_default()
            .push_back(blob);
    }

    pub fn drain(&self, to: &NodeId) -> Vec<RelayedBlob> {
        match self.inner.lock().unwrap().remove(to) {
            Some(queue) => queue.into_iter().collect(),
            None => Vec::new(),
        }
    }
}

/// `/v1/relay/blob`: accept a sealed blob from an authenticated sender and
/// queue it for the target. The rendezvous never sees plaintext.
pub struct RelayBlobEndpoint {
    peers: Arc<PeerTable>,
    queues: RelayQueues,
}

impl RelayBlobEndpoint {
    pub fn new(peers: Arc<PeerTable>, queues: RelayQueues) -> Self {
        Self { peers, queues }
    }
}

#[derive(serde::Deserialize)]
struct RelayBlobReq {
    #[allow(dead_code)]
    v: u32,
    to: String,
    from_bundle: KeyBundle,
    blob: Vec<u8>,
}

#[async_trait]
impl Endpoint for RelayBlobEndpoint {
    async fn call(&self, ctx: &CallCtx, body: serde_json::Value) -> EndpointResult {
        let req: RelayBlobReq = lep2p_transport::router::decode(body)?;
        let to = parse_node_id(&req.to)
            .ok_or_else(|| ControlError::BadRequest("bad target node_id".into()))?;
        let from = ctx.peer_node_id.ok_or_else(|| {
            ControlError::BadRequest("sender is not authenticated".into())
        })?;

        if !req.from_bundle.verify(&from) {
            return Err(ControlError::BadRequest(
                "from_bundle does not match the sender".into(),
            ));
        }
        if self.peers.get(&to).is_none() {
            return Err(ControlError::BadRequest("target not connected".into()));
        }

        self.queues.push(
            to,
            RelayedBlob {
                from: from.to_base32(),
                from_bundle: req.from_bundle,
                blob: req.blob,
            },
        );

        use lep2p_transport::router::ok;
        ok(json!({ "v": lep2p_core::SCHEMA_VERSION, "ok": true }))
    }
}

/// `/v1/relay/pull`: drain the authenticated caller's mailbox.
pub struct RelayPullEndpoint {
    queues: RelayQueues,
}

impl RelayPullEndpoint {
    pub fn new(queues: RelayQueues) -> Self {
        Self { queues }
    }
}

#[derive(serde::Deserialize)]
struct RelayPullReq {
    #[allow(dead_code)]
    v: u32,
}

#[async_trait]
impl Endpoint for RelayPullEndpoint {
    async fn call(&self, ctx: &CallCtx, body: serde_json::Value) -> EndpointResult {
        let _req: RelayPullReq = lep2p_transport::router::decode(body)?;
        let me = ctx
            .peer_node_id
            .ok_or_else(|| ControlError::BadRequest("caller is not authenticated".into()))?;
        let blobs = self.queues.drain(&me);

        use lep2p_transport::router::ok;
        ok(json!({ "v": lep2p_core::SCHEMA_VERSION, "blobs": blobs }))
    }
}

impl NatClient {
    /// Fetch a peer's verified E2EE key bundle through a rendezvous peer.
    pub async fn key_bundle(
        &self,
        rendezvous: &Peer,
        target: NodeId,
    ) -> anyhow::Result<Option<KeyBundle>> {
        let resp = rendezvous
            .request(
                "/v1/node/keys",
                json!({ "v": lep2p_core::SCHEMA_VERSION, "node_id": target.to_base32() }),
            )
            .await?;
        let value = resp
            .get("key_bundle")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Ok(serde_json::from_value(value)?)
    }

    /// Seal `payload` end-to-end for `target` and drop it into `relay`'s
    /// mailbox. The relay only ever sees ciphertext.
    pub async fn send_sealed(
        &self,
        relay: &Peer,
        target: NodeId,
        target_bundle: &KeyBundle,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        let identity = self.transport.identity();
        if !target_bundle.verify(&target) {
            anyhow::bail!("target key bundle failed verification");
        }
        let recipient_public = target_bundle
            .x25519()
            .ok_or_else(|| anyhow::anyhow!("invalid target key bundle"))?;
        let aad = lep2p_e2ee::context_aad(&identity.node_id(), &target);
        let blob = lep2p_e2ee::seal_authenticated(&identity, &recipient_public, &aad, payload);
        let from_bundle = KeyBundle::create(&identity);

        relay
            .request(
                "/v1/relay/blob",
                json!({
                    "v": lep2p_core::SCHEMA_VERSION,
                    "to": target.to_base32(),
                    "from_bundle": from_bundle,
                    "blob": blob,
                }),
            )
            .await?;
        Ok(())
    }

    /// Drain sealed blobs addressed to this node from a relay mailbox.
    pub async fn pull(&self, relay: &Peer) -> anyhow::Result<Vec<RelayedBlob>> {
        let resp = relay
            .request(
                "/v1/relay/pull",
                json!({ "v": lep2p_core::SCHEMA_VERSION }),
            )
            .await?;
        let blobs = resp.get("blobs").cloned().unwrap_or(json!([]));
        Ok(serde_json::from_value(blobs)?)
    }
}
