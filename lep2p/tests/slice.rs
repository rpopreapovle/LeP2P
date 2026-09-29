//! End-to-end vertical slice: rendezvous, NAT hole punch, DHT find_node.

use lep2p::identity::Identity;
use lep2p::transport::*;
use lep2p_core::Capabilities;
use lep2p_dht::{FindNodeEndpoint, GetEndpoint, PutEndpoint};
use lep2p_nat::{NoRelay, PunchEndpoint, ReflectEndpoint, RelayEndpoint};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

/// Build a fully-wired node (transport + control endpoints) like the daemon.
async fn serve_node(seed: &str) -> (Arc<NodeTransport>, SocketAddr, Arc<PeerTable>) {
    let identity = Identity::from_bytes(&hash_id(seed));
    let transport = Arc::new(
        NodeTransport::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            Capabilities::default(),
        )
        .await
        .unwrap(),
    );
    let peers = Arc::new(PeerTable::default());
    let table = Arc::new(RwLock::new(lep2p_dht::RoutingTable::default()));
    table.write().unwrap().set_self(transport.node_id());
    let store: Arc<RwLock<HashMap<String, (String, u64)>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let router = Arc::new(Router::default());
    router.register("/v1/hello", Hello(peers.clone()));
    router.register("/v1/nat/reflect", ReflectEndpoint);
    router.register("/v1/nat/punch", PunchEndpoint::new(peers.clone()));
    router.register("/v1/relay/offer", RelayEndpoint::new(Arc::new(NoRelay)));
    router.register(
        "/v1/dht/find_node",
        FindNodeEndpoint::new(peers.clone(), table),
    );
    router.register("/v1/dht/put", PutEndpoint::new(store.clone()));
    router.register("/v1/dht/get", GetEndpoint::new(store.clone()));

    let addr = transport.local_addr();
    let serve = transport.clone();
    tokio::spawn(async move {
        let _ = serve.serve_control(router).await;
    });
    (transport, addr, peers)
}

/// Hello endpoint registering node_id -> observed into the peer table.
struct Hello(Arc<PeerTable>);
#[async_trait::async_trait]
impl Endpoint for Hello {
    async fn call(&self, ctx: &CallCtx, body: serde_json::Value) -> EndpointResult {
        let node_id = body
            .get("node_id")
            .and_then(|v| v.as_str())
            .and_then(lep2p_core::parse_node_id)
            .ok_or_else(|| ControlError::BadRequest("bad node_id".into()))?;
        if let Some(conn) = &ctx.conn {
            self.0.insert(Peer::new(
                conn.clone(),
                node_id,
                ctx.observed,
            ));
        }
        Ok(json!({"ok": true}))
    }
}

async fn register(peer: &Peer, node_id: lep2p::identity::NodeId) {
    peer.request("/v1/hello", json!({ "node_id": node_id.to_base32() }))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn rendezvous_punch_and_dht() {
    let (r_node, r_addr, _) = serve_node("rendezvous").await;
    let (b_node, _b_addr, _) = serve_node("node-b").await;
    let (c_node, _c_addr, _) = serve_node("node-c").await;

    // B and C connect to rendezvous R and register.
    let r_peer_b = c_node.connect(r_addr, r_node.node_id()).await.unwrap();
    register(&r_peer_b, c_node.node_id()).await;
    let r_peer_c = c_node.connect(r_addr, r_node.node_id()).await.unwrap();
    let _ = r_peer_c;
    // B is the punch target: B must also connect+register so R sees B's endpoint.
    let b_side = b_node.connect(r_addr, r_node.node_id()).await.unwrap();
    register(&b_side, b_node.node_id()).await;

    // C fires a reflect against R and confirms it sees a valid observed address.
    let client = lep2p_nat::NatClient {
        transport: c_node.clone(),
    };
    let observed = client.reflect(&r_peer_b).await.unwrap();
    assert!(observed.ip().is_loopback());

    // C hole-punches toward B via R, then gets a direct connection to B.
    let direct_peer = client.hole_punch(&r_peer_b, b_node.node_id()).await.unwrap();
    assert_eq!(direct_peer.node_id, b_node.node_id());

    // DHT: C asks R to find_node for B and should receive B back.
    let resp = r_peer_b
        .request(
            "/v1/dht/find_node",
            json!({ "v": 1, "target_id": b_node.node_id().to_base32() }),
        )
        .await
        .unwrap();
    let nodes = resp["nodes"].as_array().expect("nodes array");
    assert!(!nodes.is_empty(), "find_node should return known nodes");
}

fn hash_id(seed: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(seed.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}
