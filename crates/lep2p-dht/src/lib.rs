//! Kademlia DHT for peer discovery, plus TXT DNS seeds bootstrap.

#![forbid(unsafe_code)]

mod kad;
mod seeds;

pub use kad::{Distance, KadNode, RoutingTable};
pub use seeds::{resolve_seeds, verify_seed, SeedContact, TXT_PREFIX};

use async_trait::async_trait;
use lep2p_core::{Capabilities, NodeInfo, SCHEMA_VERSION};
use lep2p_e2ee::{self, KeyBundle};
use lep2p_identity::{Identity, NodeId};
use lep2p_transport::{
    CallCtx, ControlError, Endpoint, EndpointResult, NodeTransport, Peer, PeerTable,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};

const K: usize = 20;

/// A value held by a DHT node: plaintext, or a sealed blob that only the
/// intended reader can open.
#[derive(Clone, Debug)]
pub enum StoreValue {
    /// Readable by the storing node and anyone who fetches it.
    Plain(String),
    /// Opaque ciphertext addressed to a specific node.
    Sealed(SealedRecord),
}

/// A sealed DHT record: `blob` is `lep2p_e2ee::seal` output for `to`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SealedRecord {
    /// Intended reader's `NodeId` (base32).
    pub to: String,
    /// Publisher's verified E2EE key bundle.
    pub from_bundle: KeyBundle,
    /// Sealed payload.
    pub blob: Vec<u8>,
}

/// In-memory value store: key -> (value, expiry unix timestamp).
pub type ValueStore = Arc<RwLock<HashMap<String, (StoreValue, u64)>>>;

/// Bootstrap a node at known addresses (from TXT seeds or config), verifying each
/// by recomputing overlay IPv6 from its pubkey. Returns the connected peers.
pub async fn bootstrap(
    transport: Arc<NodeTransport>,
    peers: Arc<PeerTable>,
    table: Arc<RwLock<RoutingTable>>,
    contacts: &[SeedContact],
) -> Vec<Peer> {
    let mut connected = Vec::new();
    for c in contacts {
        if let Some(peer) = try_seed_connect(&transport, &peers, &table, c).await {
            connected.push(peer);
        }
    }
    connected
}

/// Connect to one seed contact after verification.
pub async fn try_seed_connect(
    transport: &Arc<NodeTransport>,
    peers: &Arc<PeerTable>,
    table: &Arc<RwLock<RoutingTable>>,
    contact: &SeedContact,
) -> Option<Peer> {
    if contact.node_id == transport.node_id() {
        tracing::debug!("skipping self seed (identical node id)");
        return None;
    }
    if !verify_seed(contact) {
        tracing::warn!("seed failed verification, dropping: {}", contact.overlay_ipv6);
        return None;
    }
    match transport.connect(contact.socket, contact.node_id).await {
        Ok(peer) => {
            peers.insert(peer.clone());
            table.write().unwrap().insert(contact.node_id, contact.socket);
            Some(peer)
        }
        Err(e) => {
            tracing::debug!("seed connect failed: {e}");
            None
        }
    }
}

/// Kademlia `FIND_NODE` endpoint: return the K closest known nodes to `target_id`.
pub struct FindNodeEndpoint {
    peers: Arc<PeerTable>,
    table: Arc<RwLock<RoutingTable>>,
}

impl FindNodeEndpoint {
    pub fn new(peers: Arc<PeerTable>, table: Arc<RwLock<RoutingTable>>) -> Self {
        Self { peers, table }
    }

    fn closest(&self, target: NodeId, k: usize) -> Vec<NodeInfo> {
        let mut cands: Vec<(NodeId, SocketAddr)> = self
            .peers
            .all()
            .iter()
            .map(|p| (p.node_id, p.observed))
            .collect();
        cands.extend(self.table.read().unwrap().all().iter().map(|(id, s)| (*id, *s)));
        cands.dedup_by_key(|(id, _)| *id);
        cands.sort_by_key(|(id, _)| Distance::xor(&target, id));
        cands.truncate(k);
        cands
            .into_iter()
            .map(|(id, addr)| kad_node_to_info(id, addr))
            .collect()
    }
}

#[async_trait]
impl Endpoint for FindNodeEndpoint {
    async fn call(&self, _ctx: &CallCtx, body: serde_json::Value) -> EndpointResult {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Req {
            v: u32,
            target_id: String,
        }
        let req: Req = serde_json::from_value(body)
            .map_err(|e| ControlError::BadRequest(e.to_string()))?;
        let target = lep2p_core::parse_node_id(&req.target_id)
            .ok_or_else(|| ControlError::BadRequest("bad target_id".into()))?;
        let near = self.closest(target, K);
        Ok(json!({ "v": SCHEMA_VERSION, "nodes": near }))
    }
}

/// In-memory `PUT` value-store endpoint.
///
/// Accepts either a plaintext `value` or a `sealed` record. A sealed record is
/// stored verbatim: the storing node cannot read it. The publisher's bundle is
/// checked against the TLS-authenticated sender, so records cannot be planted
/// under someone else's identity.
pub struct PutEndpoint {
    store: ValueStore,
}

impl PutEndpoint {
    pub fn new(store: ValueStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl Endpoint for PutEndpoint {
    async fn call(&self, ctx: &CallCtx, body: serde_json::Value) -> EndpointResult {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Req {
            v: u32,
            key: String,
            ttl: u32,
            #[serde(default)]
            value: Option<String>,
            #[serde(default)]
            sealed: Option<SealedRecord>,
        }
        let req: Req =
            serde_json::from_value(body).map_err(|e| ControlError::BadRequest(e.to_string()))?;

        let value = match (req.value, req.sealed) {
            (Some(value), None) => StoreValue::Plain(value),
            (None, Some(sealed)) => {
                let sender = ctx.peer_node_id.ok_or_else(|| {
                    ControlError::BadRequest("publisher is not authenticated".into())
                })?;
                if !sealed.from_bundle.verify(&sender) {
                    return Err(ControlError::BadRequest(
                        "from_bundle does not match the publisher".into(),
                    ));
                }
                StoreValue::Sealed(sealed)
            }
            _ => {
                return Err(ControlError::BadRequest(
                    "provide exactly one of `value` or `sealed`".into(),
                ))
            }
        };

        let exp = now_ts() + req.ttl as u64;
        self.store.write().unwrap().insert(req.key, (value, exp));
        Ok(json!({ "v": SCHEMA_VERSION, "stored": true }))
    }
}

/// In-memory `GET` value-store endpoint.
///
/// Returns `value` for plaintext records or `sealed` for opaque ones; the
/// storing node never decrypts anything.
pub struct GetEndpoint {
    store: ValueStore,
}

impl GetEndpoint {
    pub fn new(store: ValueStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl Endpoint for GetEndpoint {
    async fn call(&self, _ctx: &CallCtx, body: serde_json::Value) -> EndpointResult {
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Req {
            v: u32,
            key: String,
        }
        let req: Req =
            serde_json::from_value(body).map_err(|e| ControlError::BadRequest(e.to_string()))?;

        let entry = {
            let s = self.store.read().unwrap();
            s.get(&req.key).cloned()
        };
        let (value, sealed) = match entry {
            Some((StoreValue::Plain(v), _)) => (Some(v), None),
            Some((StoreValue::Sealed(s), _)) => (None, Some(s)),
            None => (None, None),
        };
        Ok(json!({ "v": SCHEMA_VERSION, "value": value, "sealed": sealed, "nodes": [] }))
    }
}

fn kad_node_to_info(id: NodeId, addr: SocketAddr) -> NodeInfo {
    NodeInfo {
        node_id: id.to_base32(),
        overlay_ipv6: overlay_for(id).to_string(),
        public_addr: Some(addr),
        capabilities: Capabilities::default(),
    }
}

/// Reconstruct the overlay IPv6 for a NodeId (fd00::/16 + 14 bytes of hash).
pub fn overlay_for(id: NodeId) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1] = 0x00;
    octets[2..].copy_from_slice(&id.0[..14]);
    octets.into()
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Convenience: a node's NodeId.
pub fn node_id_of(identity: &Identity) -> NodeId {
    identity.node_id()
}

/// Standalone facade wiring transport + peer table + routing table together.
pub struct DhtNode {
    pub transport: Arc<NodeTransport>,
    pub peers: Arc<PeerTable>,
    pub table: Arc<RwLock<RoutingTable>>,
    pub store: ValueStore,
}

impl DhtNode {
    pub fn new(transport: Arc<NodeTransport>) -> Self {
        Self {
            transport,
            peers: Arc::new(PeerTable::default()),
            table: Arc::new(RwLock::new(RoutingTable::default())),
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Seal `payload` for the reader described by `reader_bundle` and store it
    /// under `key` on `peer`. The storing node only sees ciphertext.
    pub async fn put_sealed(
        &self,
        peer: &Peer,
        key: &str,
        reader_bundle: &KeyBundle,
        payload: &[u8],
        ttl: u32,
    ) -> anyhow::Result<()> {
        let identity = self.transport.identity();
        let reader_id = reader_bundle
            .node_id()
            .ok_or_else(|| anyhow::anyhow!("invalid reader key bundle"))?;
        let shared = reader_bundle
            .shared_key_with(&identity)
            .ok_or_else(|| anyhow::anyhow!("invalid reader key bundle"))?;
        let aad = lep2p_e2ee::context_aad(&identity.node_id(), &reader_id);
        let blob = lep2p_e2ee::seal(&shared, &aad, payload);

        let sealed = SealedRecord {
            to: reader_id.to_base32(),
            from_bundle: KeyBundle::create(&identity),
            blob,
        };
        let resp = peer
            .request(
                "/v1/dht/put",
                json!({ "v": SCHEMA_VERSION, "key": key, "ttl": ttl, "sealed": sealed }),
            )
            .await?;
        if resp.get("stored").and_then(|v| v.as_bool()) != Some(true) {
            anyhow::bail!("dht put rejected: {resp}");
        }
        Ok(())
    }

    /// Fetch a record from `peer` and open it if it is sealed to this node.
    /// Returns `Ok(None)` when the key is absent; errors if a sealed record is
    /// addressed to someone else or fails authentication.
    pub async fn get_sealed(&self, peer: &Peer, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let resp = peer
            .request(
                "/v1/dht/get",
                json!({ "v": SCHEMA_VERSION, "key": key }),
            )
            .await?;

        if let Some(value) = resp.get("value").and_then(|v| v.as_str()) {
            return Ok(Some(value.as_bytes().to_vec()));
        }
        let Some(sealed_value) = resp.get("sealed").filter(|v| !v.is_null()) else {
            return Ok(None);
        };

        let sealed: SealedRecord = serde_json::from_value(sealed_value.clone())?;
        let identity = self.transport.identity();
        let from_id = sealed
            .from_bundle
            .node_id()
            .ok_or_else(|| anyhow::anyhow!("invalid sender bundle"))?;
        if !sealed.from_bundle.verify(&from_id) {
            anyhow::bail!("sender bundle failed verification");
        }
        let to = lep2p_core::parse_node_id(&sealed.to)
            .ok_or_else(|| anyhow::anyhow!("invalid recipient id"))?;
        if to != identity.node_id() {
            anyhow::bail!("record is sealed to a different node");
        }
        let shared = sealed
            .from_bundle
            .shared_key_with(&identity)
            .ok_or_else(|| anyhow::anyhow!("key agreement failed"))?;
        let aad = lep2p_e2ee::context_aad(&from_id, &to);
        Ok(Some(lep2p_e2ee::open(&shared, &aad, &sealed.blob)?))
    }

    /// Bootstrap from TXT DNS seeds; returns connected peers.
    pub async fn bootstrap(&self, seed_hosts: &[String]) -> anyhow::Result<Vec<Peer>> {
        let mut contacts = Vec::new();
        for host in seed_hosts {
            match resolve_seeds(host).await {
                Ok(cs) => contacts.extend(cs),
                Err(e) => tracing::warn!("seed {host}: {e}"),
            }
        }
        Ok(bootstrap(
            self.transport.clone(),
            self.peers.clone(),
            self.table.clone(),
            &contacts,
        )
        .await)
    }
}

