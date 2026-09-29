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

/// Domain separation for signed DHT records.
const SIGNED_RECORD_DOMAIN: &[u8] = b"lep2p-dht-record-v1";

/// A value held by a DHT node: plaintext, sealed, or signed.
#[derive(Clone, Debug)]
pub enum StoreValue {
    /// Readable by the storing node and anyone who fetches it. Not authenticated.
    Plain(String),
    /// Opaque ciphertext addressed to a specific node.
    Sealed(SealedRecord),
    /// Plaintext signed by its publisher; readers can detect tampering.
    Signed(SignedRecord),
}

/// A plaintext record signed by its publisher.
///
/// The signature covers `(key, value)`, so a storage node cannot alter either
/// without detection. The first authenticated record under a key owns it:
/// later records under the same key must come from the same publisher.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SignedRecord {
    /// The record value.
    pub value: String,
    /// Publisher's verified E2EE key bundle.
    pub from_bundle: KeyBundle,
    /// ed25519 signature over the framed `(key, value)` message.
    pub sig: Vec<u8>,
}

impl SignedRecord {
    /// Sign `value` under `key` with the publisher's identity.
    pub fn create(identity: &Identity, key: &str, value: &str) -> Self {
        let sig = lep2p_e2ee::sign_parts(
            identity,
            SIGNED_RECORD_DOMAIN,
            &[key.as_bytes(), value.as_bytes()],
        );
        Self {
            value: value.to_string(),
            from_bundle: KeyBundle::create(identity),
            sig: sig.to_vec(),
        }
    }

    /// The publisher this record claims.
    pub fn publisher(&self) -> Option<NodeId> {
        self.from_bundle.node_id()
    }

    /// Verify the record against the storage key and an expected publisher.
    pub fn verify(&self, key: &str, expected: &NodeId) -> bool {
        lep2p_e2ee::verify_parts(
            &self.from_bundle,
            expected,
            SIGNED_RECORD_DOMAIN,
            &[key.as_bytes(), self.value.as_bytes()],
            &self.sig,
        )
    }
}

/// The publisher that owns a stored value, if any authenticated record.
fn owner_of(value: &StoreValue) -> Option<NodeId> {
    match value {
        StoreValue::Plain(_) => None,
        StoreValue::Sealed(record) => record.from_bundle.node_id(),
        StoreValue::Signed(record) => record.publisher(),
    }
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
            #[serde(default)]
            signed: Option<SignedRecord>,
        }
        let req: Req =
            serde_json::from_value(body).map_err(|e| ControlError::BadRequest(e.to_string()))?;

        let value = match (req.value, req.sealed, req.signed) {
            (Some(value), None, None) => StoreValue::Plain(value),
            (None, Some(sealed), None) => {
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
            (None, None, Some(record)) => {
                let sender = ctx.peer_node_id.ok_or_else(|| {
                    ControlError::BadRequest("publisher is not authenticated".into())
                })?;
                if record.publisher() != Some(sender) {
                    return Err(ControlError::BadRequest(
                        "signed record publisher does not match the sender".into(),
                    ));
                }
                if !record.verify(&req.key, &sender) {
                    return Err(ControlError::BadRequest("invalid record signature".into()));
                }
                StoreValue::Signed(record)
            }
            _ => {
                return Err(ControlError::BadRequest(
                    "provide exactly one of `value`, `sealed`, or `signed`".into(),
                ))
            }
        };

        // The first authenticated record under a key owns it: reject
        // overwrites from other publishers and unsigned overwrites of owned keys.
        let existing = self
            .store
            .read()
            .unwrap()
            .get(&req.key)
            .map(|(v, _)| v.clone());
        if let Some(existing) = existing {
            match (owner_of(&existing), owner_of(&value)) {
                (Some(owner), Some(new_owner)) if owner != new_owner => {
                    return Err(ControlError::BadRequest(
                        "key is owned by another publisher".into(),
                    ));
                }
                (Some(_), None) => {
                    return Err(ControlError::BadRequest(
                        "key is owned by a publisher; a signed or sealed record is required".into(),
                    ));
                }
                _ => {}
            }
        }

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
        let (value, sealed, signed) = match entry {
            Some((StoreValue::Plain(v), _)) => (Some(v), None, None),
            Some((StoreValue::Sealed(s), _)) => (None, Some(s), None),
            Some((StoreValue::Signed(s), _)) => (None, None, Some(s)),
            None => (None, None, None),
        };
        Ok(
            json!({ "v": SCHEMA_VERSION, "value": value, "sealed": sealed, "signed": signed, "nodes": [] }),
        )
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
    lep2p_core::overlay_for(&id)
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
        if !reader_bundle.verify(&reader_id) {
            anyhow::bail!("reader key bundle failed verification");
        }
        let reader_public = reader_bundle
            .x25519()
            .ok_or_else(|| anyhow::anyhow!("invalid reader key bundle"))?;
        let aad = lep2p_e2ee::context_aad(&identity.node_id(), &reader_id);
        let blob = lep2p_e2ee::seal_authenticated(&identity, &reader_public, &aad, payload);

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
        let sender_public = sealed
            .from_bundle
            .x25519()
            .ok_or_else(|| anyhow::anyhow!("invalid sender key"))?;
        let aad = lep2p_e2ee::context_aad(&from_id, &to);
        Ok(Some(lep2p_e2ee::open_authenticated(
            &identity,
            &sender_public,
            &aad,
            &sealed.blob,
        )?))
    }

    /// Store a signed plaintext record under `key` on `peer`.
    pub async fn put_signed(
        &self,
        peer: &Peer,
        key: &str,
        value: &str,
        ttl: u32,
    ) -> anyhow::Result<()> {
        let record = SignedRecord::create(&self.transport.identity(), key, value);
        let resp = peer
            .request(
                "/v1/dht/put",
                json!({ "v": SCHEMA_VERSION, "key": key, "ttl": ttl, "signed": record }),
            )
            .await?;
        if resp.get("stored").and_then(|v| v.as_bool()) != Some(true) {
            anyhow::bail!("dht put rejected: {resp}");
        }
        Ok(())
    }

    /// Fetch a record and verify its signature.
    ///
    /// When `expected_publisher` is set, the record must be signed by exactly
    /// that node — plaintext records are rejected, so the queried storage node
    /// cannot swap in unauthenticated data. Returns `Ok(None)` if the key is
    /// absent.
    pub async fn get_signed(
        &self,
        peer: &Peer,
        key: &str,
        expected_publisher: Option<NodeId>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let resp = peer
            .request(
                "/v1/dht/get",
                json!({ "v": SCHEMA_VERSION, "key": key }),
            )
            .await?;

        if let Some(signed_value) = resp.get("signed").filter(|v| !v.is_null()) {
            let record: SignedRecord = serde_json::from_value(signed_value.clone())?;
            let publisher = record
                .publisher()
                .ok_or_else(|| anyhow::anyhow!("invalid record publisher"))?;
            if let Some(expected) = expected_publisher {
                if publisher != expected {
                    anyhow::bail!("record publisher mismatch");
                }
            }
            if !record.verify(key, &publisher) {
                anyhow::bail!("record signature verification failed");
            }
            return Ok(Some(record.value.into_bytes()));
        }

        if let Some(value) = resp.get("value").and_then(|v| v.as_str()) {
            if expected_publisher.is_some() {
                anyhow::bail!("record is not signed");
            }
            return Ok(Some(value.as_bytes().to_vec()));
        }

        if resp.get("sealed").map(|v| !v.is_null()).unwrap_or(false) {
            anyhow::bail!("record is sealed, use get_sealed");
        }
        Ok(None)
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


#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> Identity {
        Identity::from_bytes(&[seed; 32])
    }

    #[test]
    fn signed_record_roundtrip_and_tamper() {
        let a = identity(1);
        let b = identity(2);
        let record = SignedRecord::create(&a, "profile", "v1");

        assert!(record.verify("profile", &a.node_id()));
        // Replayed under another key.
        assert!(!record.verify("other", &a.node_id()));
        // Claimed as another publisher.
        assert!(!record.verify("profile", &b.node_id()));

        let mut tampered = record.clone();
        tampered.value = "v2".into();
        assert!(!tampered.verify("profile", &a.node_id()));
    }

    #[test]
    fn ownership_tracks_authenticated_publishers() {
        let a = identity(1);
        let stored = StoreValue::Signed(SignedRecord::create(&a, "k", "v"));
        assert_eq!(owner_of(&stored), Some(a.node_id()));
        assert_eq!(owner_of(&StoreValue::Plain("v".into())), None);
    }
}
