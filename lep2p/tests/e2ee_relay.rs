//! E2EE relay slice: A seals a payload for B and drops it into the
//! rendezvous R's mailbox; B pulls and opens it. R only ever sees ciphertext,
//! and claimed node ids are bound to the TLS client certificates.

use lep2p::e2ee::{self, KeyBundle};
use lep2p::identity::Identity;
use lep2p::nat::{
    HelloEndpoint, NatClient, NodeKeysEndpoint, ReflectEndpoint, RelayBlobEndpoint,
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
    let queues = RelayQueues::default();

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

/// Register `node` at `rendezvous` with its signed E2EE key bundle.
async fn register(peer: &Peer, node: &Arc<NodeTransport>) {
    let bundle = KeyBundle::create(&node.identity());
    let resp = peer
        .request(
            "/v1/hello",
            json!({
                "v": 1,
                "node_id": node.node_id().to_base32(),
                "key_bundle": bundle,
            }),
        )
        .await
        .unwrap();
    assert_eq!(resp["ok"], json!(true));
}

#[tokio::test(flavor = "multi_thread")]
async fn sealed_blob_relays_without_plaintext_exposure() {
    let (r_node, r_addr) = serve_node("rendezvous-e2ee").await;
    let (a_node, _a_addr) = serve_node("node-a-e2ee").await;
    let (b_node, _b_addr) = serve_node("node-b-e2ee").await;

    // B and A register with the rendezvous, publishing their key bundles.
    let b_to_r = b_node.connect(r_addr, r_node.node_id()).await.unwrap();
    register(&b_to_r, &b_node).await;
    let a_to_r = a_node.connect(r_addr, r_node.node_id()).await.unwrap();
    register(&a_to_r, &a_node).await;

    // A learns B's verified key bundle through R.
    let a_client = NatClient {
        transport: a_node.clone(),
    };
    let b_bundle = a_client
        .key_bundle(&a_to_r, b_node.node_id())
        .await
        .unwrap()
        .expect("B published a key bundle");
    assert!(b_bundle.verify(&b_node.node_id()));

    // A seals a payload for B and sends it through R.
    let secret: &[u8] = b"top secret: the rendezvous must not read this";
    a_client
        .send_sealed(&a_to_r, b_node.node_id(), &b_bundle, secret)
        .await
        .unwrap();

    // B pulls its mailbox and opens the blob end-to-end.
    let b_client = NatClient {
        transport: b_node.clone(),
    };
    let blobs = b_client.pull(&b_to_r).await.unwrap();
    assert_eq!(blobs.len(), 1, "exactly one relayed blob");
    let relayed = &blobs[0];
    assert_eq!(relayed.from, a_node.node_id().to_base32());
    assert!(relayed.from_bundle.verify(&a_node.node_id()));

    // The relayed ciphertext must not contain the plaintext.
    assert!(
        !relayed.blob.windows(secret.len()).any(|w| w == secret),
        "ciphertext leaked plaintext"
    );

    let key = relayed
        .from_bundle
        .shared_key_with(&b_node.identity())
        .expect("shared key");
    let aad = e2ee::context_aad(&a_node.node_id(), &b_node.node_id());
    let opened = e2ee::open(&key, &aad, &relayed.blob).expect("B opens the sealed blob");
    assert_eq!(opened.as_slice(), secret);
}

#[tokio::test(flavor = "multi_thread")]
async fn hello_rejects_node_id_spoofing() {
    let (r_node, r_addr) = serve_node("rendezvous-spoof").await;
    let (a_node, _a_addr) = serve_node("node-a-spoof").await;
    let (b_node, _b_addr) = serve_node("node-b-spoof").await;

    let a_to_r = a_node.connect(r_addr, r_node.node_id()).await.unwrap();

    // A tries to register as B; the server must reject it because the
    // claimed id does not match A's TLS client certificate.
    let resp = a_to_r
        .request(
            "/v1/hello",
            json!({ "v": 1, "node_id": b_node.node_id().to_base32() }),
        )
        .await
        .unwrap();
    assert_eq!(resp["ok"], json!(false));
}

fn hash_id(seed: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(seed.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}
