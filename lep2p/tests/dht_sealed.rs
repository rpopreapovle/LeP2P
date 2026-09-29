//! Sealed DHT records: a storage node keeps values as ciphertext, and only
//! the intended reader can open them end-to-end.

use lep2p::dht::{DhtNode, GetEndpoint, PutEndpoint, StoreValue, ValueStore};
use lep2p::e2ee::KeyBundle;
use lep2p::identity::Identity;
use lep2p::nat::{HelloEndpoint, NatClient, NodeKeysEndpoint, ReflectEndpoint};
use lep2p::transport::*;
use lep2p_core::Capabilities;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

async fn serve_node(seed: &str) -> (Arc<NodeTransport>, SocketAddr, ValueStore) {
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
    let store: ValueStore = Arc::new(RwLock::new(HashMap::new()));

    let router = Arc::new(Router::default());
    router.register("/v1/hello", HelloEndpoint::new(peers.clone()));
    router.register("/v1/node/keys", NodeKeysEndpoint::new(peers.clone()));
    router.register("/v1/dht/put", PutEndpoint::new(store.clone()));
    router.register("/v1/dht/get", GetEndpoint::new(store.clone()));
    router.register("/v1/nat/reflect", ReflectEndpoint);

    let addr = transport.local_addr();
    let serve = transport.clone();
    tokio::spawn(async move {
        let _ = serve.serve_control(router).await;
    });
    (transport, addr, store)
}

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
async fn storage_node_cannot_read_sealed_records() {
    let (d_node, d_addr, d_store) = serve_node("dht-storage").await;
    let (a_node, _a_addr, _) = serve_node("dht-publisher").await;
    let (b_node, _b_addr, _) = serve_node("dht-reader").await;

    // Reader and publisher register at the storage node.
    let b_to_d = b_node.connect(d_addr, d_node.node_id()).await.unwrap();
    register(&b_to_d, &b_node).await;
    let a_to_d = a_node.connect(d_addr, d_node.node_id()).await.unwrap();
    register(&a_to_d, &a_node).await;

    // Publisher learns the reader's verified key bundle from the storage node.
    let a_client = NatClient {
        transport: a_node.clone(),
    };
    let b_bundle = a_client
        .key_bundle(&a_to_d, b_node.node_id())
        .await
        .unwrap()
        .expect("reader published a key bundle");

    // Publisher stores a sealed record.
    let a_dht = DhtNode::new(a_node.clone());
    let secret: &[u8] = b"sealed DHT payload; the storage node must not read this";
    a_dht
        .put_sealed(&a_to_d, "friend-card", &b_bundle, secret, 3600)
        .await
        .unwrap();

    // The storage node holds only ciphertext.
    {
        let store = d_store.read().unwrap();
        let (value, _expires) = store.get("friend-card").expect("record stored");
        match value {
            StoreValue::Sealed(record) => {
                assert_eq!(record.to, b_node.node_id().to_base32());
                assert!(
                    !record.blob.windows(secret.len()).any(|w| w == secret),
                    "stored ciphertext leaked the plaintext"
                );
            }
            StoreValue::Plain(_) | StoreValue::Signed(_) => {
                panic!("record must be sealed")
            }
        }
    }

    // The reader fetches and opens it end-to-end.
    let b_dht = DhtNode::new(b_node.clone());
    let opened = b_dht
        .get_sealed(&b_to_d, "friend-card")
        .await
        .unwrap()
        .expect("sealed record present");
    assert_eq!(opened.as_slice(), secret);

    // Someone other than the reader cannot open it.
    let err = a_dht.get_sealed(&a_to_d, "friend-card").await;
    assert!(
        err.is_err(),
        "a record sealed to another node must not be opened"
    );
}

fn hash_id(seed: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(seed.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}
