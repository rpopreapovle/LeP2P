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

/// Bounds protecting relay mailboxes from abuse and unbounded growth.
#[derive(Clone, Debug)]
pub struct RelayLimits {
    /// Maximum number of queued blobs per target node.
    pub max_blobs_per_target: usize,
    /// Maximum size of a single sealed blob, in bytes.
    pub max_blob_bytes: usize,
    /// Maximum total queued bytes across all mailboxes.
    pub max_total_bytes: usize,
    /// Default time-to-live for queued blobs, in seconds.
    pub default_ttl_secs: u64,
    /// Upper bound for publisher-supplied TTLs, in seconds.
    pub max_ttl_secs: u64,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_blobs_per_target: 64,
            max_blob_bytes: 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            default_ttl_secs: 300,
            max_ttl_secs: 3600,
        }
    }
}

/// Why a mailbox rejected a blob.
#[derive(Debug, thiserror::Error)]
pub enum MailboxError {
    #[error("blob too large")]
    BlobTooLarge,
    #[error("mailbox full")]
    MailboxFull,
    #[error("relay storage exhausted")]
    StorageExhausted,
}

#[derive(Default)]
struct RelayState {
    mailboxes: HashMap<NodeId, VecDeque<QueuedBlob>>,
    total_bytes: usize,
}

struct QueuedBlob {
    blob: RelayedBlob,
    expires_at: u64,
}

/// Per-target mailboxes of sealed blobs awaiting pickup.
///
/// Bounded by [`RelayLimits`]: per-blob size, per-target count, and total
/// queued bytes. Expired blobs are dropped lazily.
#[derive(Clone, Default)]
pub struct RelayQueues {
    limits: RelayLimits,
    state: Arc<Mutex<RelayState>>,
}

impl RelayQueues {
    pub fn new(limits: RelayLimits) -> Self {
        Self {
            limits,
            state: Arc::new(Mutex::new(RelayState::default())),
        }
    }

    /// Queue a sealed blob for `to` with an optional TTL in seconds (clamped
    /// to `limits.max_ttl_secs`; defaults to `limits.default_ttl_secs`).
    pub fn push(
        &self,
        to: NodeId,
        blob: RelayedBlob,
        ttl_secs: Option<u64>,
    ) -> Result<(), MailboxError> {
        if blob.blob.len() > self.limits.max_blob_bytes {
            return Err(MailboxError::BlobTooLarge);
        }
        let ttl = ttl_secs
            .unwrap_or(self.limits.default_ttl_secs)
            .clamp(1, self.limits.max_ttl_secs.max(1));
        let expires_at = now_ts() + ttl;

        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        if let Some(queue) = state.mailboxes.get_mut(&to) {
            let freed = purge_expired(queue);
            state.total_bytes = state.total_bytes.saturating_sub(freed);
        }
        let queued = state.mailboxes.get(&to).map(VecDeque::len).unwrap_or(0);
        if queued >= self.limits.max_blobs_per_target {
            return Err(MailboxError::MailboxFull);
        }
        if state.total_bytes + blob.blob.len() > self.limits.max_total_bytes {
            return Err(MailboxError::StorageExhausted);
        }
        state.total_bytes += blob.blob.len();
        state
            .mailboxes
            .entry(to)
            .or_default()
            .push_back(QueuedBlob { blob, expires_at });
        Ok(())
    }

    /// Drain non-expired blobs for `to`, freeing their storage.
    pub fn drain(&self, to: &NodeId) -> Vec<RelayedBlob> {
        let mut state = self.state.lock().unwrap();
        let Some(mut queue) = state.mailboxes.remove(to) else {
            return Vec::new();
        };
        let now = now_ts();
        let mut out = Vec::with_capacity(queue.len());
        while let Some(entry) = queue.pop_front() {
            state.total_bytes = state.total_bytes.saturating_sub(entry.blob.blob.len());
            if entry.expires_at > now {
                out.push(entry.blob);
            }
        }
        out
    }

    /// Total queued bytes (including not-yet-purged expired entries).
    pub fn total_bytes(&self) -> usize {
        self.state.lock().unwrap().total_bytes
    }

    /// Number of queued (non-expired) blobs for `to`.
    pub fn queued(&self, to: &NodeId) -> usize {
        let mut guard = self.state.lock().unwrap();
        let state = &mut *guard;
        let mut count = 0;
        if let Some(queue) = state.mailboxes.get_mut(to) {
            let freed = purge_expired(queue);
            state.total_bytes = state.total_bytes.saturating_sub(freed);
            count = queue.len();
        }
        count
    }
}

/// Drop expired entries and return the number of bytes freed.
fn purge_expired(queue: &mut VecDeque<QueuedBlob>) -> usize {
    let now = now_ts();
    let mut freed = 0usize;
    queue.retain(|entry| {
        let keep = entry.expires_at > now;
        if !keep {
            freed += entry.blob.blob.len();
        }
        keep
    });
    freed
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    #[serde(default)]
    ttl: Option<u64>,
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

        self.queues
            .push(
                to,
                RelayedBlob {
                    from: from.to_base32(),
                    from_bundle: req.from_bundle,
                    blob: req.blob,
                },
                req.ttl,
            )
            .map_err(|e| ControlError::BadRequest(e.to_string()))?;

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

        let resp = relay
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
        if resp.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            anyhow::bail!(
                "relay rejected blob: {}",
                resp.get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown error")
            );
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use lep2p_identity::Identity;

    fn queues(limits: RelayLimits) -> RelayQueues {
        RelayQueues::new(limits)
    }

    fn node(seed: u8) -> NodeId {
        Identity::from_bytes(&[seed; 32]).node_id()
    }

    fn blob(size: usize) -> RelayedBlob {
        RelayedBlob {
            from: "sender".into(),
            from_bundle: KeyBundle::create(&Identity::from_bytes(&[9u8; 32])),
            blob: vec![7u8; size],
        }
    }

    #[test]
    fn push_drain_roundtrip_frees_storage() {
        let q = queues(RelayLimits::default());
        let to = node(1);
        q.push(to, blob(10), None).unwrap();
        q.push(to, blob(20), None).unwrap();
        assert_eq!(q.queued(&to), 2);
        assert_eq!(q.total_bytes(), 30);

        let drained = q.drain(&to);
        assert_eq!(drained.len(), 2);
        assert_eq!(q.total_bytes(), 0);
        assert!(q.drain(&to).is_empty());
    }

    #[test]
    fn oversize_blob_is_rejected() {
        let q = queues(RelayLimits {
            max_blob_bytes: 4,
            ..Default::default()
        });
        assert!(matches!(
            q.push(node(1), blob(5), None),
            Err(MailboxError::BlobTooLarge)
        ));
    }

    #[test]
    fn full_mailbox_is_rejected() {
        let q = queues(RelayLimits {
            max_blobs_per_target: 1,
            ..Default::default()
        });
        let to = node(1);
        assert!(q.push(to, blob(1), None).is_ok());
        assert!(matches!(
            q.push(to, blob(1), None),
            Err(MailboxError::MailboxFull)
        ));
    }

    #[test]
    fn aggregate_storage_limit_is_enforced() {
        let q = queues(RelayLimits {
            max_blob_bytes: 4,
            max_total_bytes: 4,
            ..Default::default()
        });
        assert!(q.push(node(1), blob(4), None).is_ok());
        assert!(matches!(
            q.push(node(2), blob(1), None),
            Err(MailboxError::StorageExhausted)
        ));
    }

    #[test]
    fn expired_blobs_are_dropped() {
        let q = queues(RelayLimits::default());
        let to = node(1);
        q.push(to, blob(8), None).unwrap();
        {
            let mut state = q.state.lock().unwrap();
            for queue in state.mailboxes.values_mut() {
                for entry in queue.iter_mut() {
                    entry.expires_at = 0;
                }
            }
        }
        assert!(q.drain(&to).is_empty());
        assert_eq!(q.total_bytes(), 0);
    }

    #[test]
    fn ttl_is_clamped_to_max() {
        let q = queues(RelayLimits {
            max_ttl_secs: 10,
            ..Default::default()
        });
        let to = node(1);
        q.push(to, blob(1), Some(3600)).unwrap();
        let state = q.state.lock().unwrap();
        let expires_at = state.mailboxes[&to][0].expires_at;
        assert!(expires_at <= now_ts() + 10);
    }
}
