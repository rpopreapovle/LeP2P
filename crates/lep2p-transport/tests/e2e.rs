use lep2p_core::Capabilities;
use lep2p_identity::Identity;
use lep2p_transport::{Endpoint, EndpointResult, NodeTransport, Router};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

struct Echo;

#[async_trait::async_trait]
impl Endpoint for Echo {
    async fn call(
        &self,
        _ctx: &lep2p_transport::CallCtx,
        body: serde_json::Value,
    ) -> EndpointResult {
        let text = body.get("m").cloned().unwrap_or(json!(""));
        Ok(json!({ "ok": true, "echo": text }))
    }
}

async fn bind_node(id: &str) -> (Arc<NodeTransport>, SocketAddr) {
    let identity = Identity::from_bytes(&blake3_node_id(id));
    let caps = Capabilities::default();
    let node = Arc::new(
        NodeTransport::bind(
            identity,
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            caps,
        )
        .await
        .unwrap(),
    );
    let router = Arc::new(Router::default());
    router.register("/v1/echo", Echo);
    let addr = node.local_addr();
    let serve = node.clone();
    tokio::spawn(async move {
        let _ = serve.serve_control(router).await;
    });
    let _ = id;
    (node, addr)
}

#[tokio::test(flavor = "multi_thread")]
async fn two_nodes_e2ee_http3() {
    let (a, a_addr) = bind_node("node-a").await;
    let (b, _b_addr) = bind_node("node-b").await;

    let peer = b
        .connect(a_addr, a.node_id())
        .await
        .expect("b -> a control connect");

    let resp = peer
        .request("/v1/echo", json!({ "m": "hello" }))
        .await
        .expect("post /v1/echo");

    assert_eq!(resp["ok"], json!(true));
    assert_eq!(resp["echo"], json!("hello"));
    assert_eq!(a.node_id(), peer.node_id);
}

fn blake3_node_id(seed: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(seed.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}
