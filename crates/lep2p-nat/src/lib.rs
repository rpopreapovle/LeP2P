//! NAT traversal: binding reflection (our own STUN analog), UDP hole punching,
//! and the relay/TURN pluggable trait (stub in M1).

#![forbid(unsafe_code)]

use async_trait::async_trait;
use lep2p_core::{
    parse_node_id, NatCapabilities, NatMethod, PunchIntent, PunchReq, PunchResp, ReflectReq,
    ReflectResp,
};
use lep2p_identity::NodeId;
use lep2p_transport::{CallCtx, ControlError, Endpoint, EndpointResult, Peer, PeerTable};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

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
