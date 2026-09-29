//! Relay mailbox limits: oversized blobs and full mailboxes are rejected,
//! and the reader still receives what was queued.

use lep2p::e2ee::KeyBundle;
use lep2p::identity::Identity;
use lep2p::nat::{
    HelloEndpoint, NatClient, NodeKeysEndpoint, ReflectEndpoint, RelayBlobEndpoint, RelayLimits,
    RelayPullEndpoint, RelayQueues,
};
use lep2p::transport::*;
use lep2p_core::Capabilities;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

async fn serve_node(seed: &str) -> (Arc<NodeTransport>, SocketAddr) {
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
    let queues = RelayQueues::new(RelayLimits {
        max_blob_bytes: 256,
        max_blobs_per_target: 1,
        ..Default::default()
    });

    let router = Arc::new(Router::default());
    router.register("/v1/hello", HelloEndpoint::new(peers.clone()));
    router.register("/v1/node/keys", NodeKeysEndpoint::new(peers.clone()));
    router.register(
        "/v1/relay/blob",
        RelayBlobEndpoint::new(peers.clone(), queues.clone()),
    );
    router.register("/v1/relay/pull", RelayPullEndpoint::new(queues));
    router.register("/v1/nat/reflect", ReflectEndpoint);

    let addr = transport.local_addr();
    let serve = transport.clone();
    tokio::spawn(async move {
        let _ = serve.serve_control(router).await;
    });
    (transport, addr)
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_limits_reject_oversize_and_full_mailbox() {
    let (r_node, r_addr) = serve_node("relay-limits").await;
    let (a_node, _a_addr) = serve_node("limits-a").await;
    let (b_node, _b_addr) = serve_node("limits-b").await;

    // Reader registers at the relay.
    let b_to_r = b_node.connect(r_addr, r_node.node_id()).await.unwrap();
    let b_key = KeyBundle::create(&b_node.identity());
    let resp = b_to_r
        .request(
            "/v1/hello",
            json!({
                "v": 1,
                "node_id": b_node.node_id().to_base32(),
                "key_bundle": b_key,
            }),
        )
        .await
        .unwrap();
    assert_eq!(resp["ok"], json!(true));

    // Publisher learns the reader's bundle and sends through the relay.
    let a_to_r = a_node.connect(r_addr, r_node.node_id()).await.unwrap();
    let a_client = NatClient {
        transport: a_node.clone(),
    };
    let b_bundle = a_client
        .key_bundle(&a_to_r, b_node.node_id())
        .await
        .unwrap()
        .expect("reader bundle");

    // Oversized sealed payload (512 + ~60 bytes of box overhead > 256).
    let overflow = vec![0u8; 512];
    let err = a_client
        .send_sealed(&a_to_r, b_node.node_id(), &b_bundle, &overflow)
        .await
        .expect_err("oversize blob must be rejected");
    assert!(
        err.to_string().contains("blob too large"),
        "unexpected error: {err}"
    );

    // The first small blob fits…
    a_client
        .send_sealed(&a_to_r, b_node.node_id(), &b_bundle, b"small")
        .await
        .unwrap();
    // …the second one hits the per-target mailbox limit.
    let err = a_client
        .send_sealed(&a_to_r, b_node.node_id(), &b_bundle, b"small")
        .await
        .expect_err("full mailbox must reject new blobs");
    assert!(
        err.to_string().contains("mailbox full"),
        "unexpected error: {err}"
    );

    // The reader still receives the queued blob.
    let b_client = NatClient {
        transport: b_node.clone(),
    };
    let blobs = b_client.pull(&b_to_r).await.unwrap();
    assert_eq!(blobs.len(), 1);
}

fn hash_id(seed: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(seed.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}
