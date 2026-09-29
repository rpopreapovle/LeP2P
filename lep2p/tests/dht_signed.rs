//! Signed DHT records: readers detect storage-node tampering, and the first
//! authenticated publisher owns a key (no record hijacking).

use lep2p::dht::{DhtNode, GetEndpoint, PutEndpoint, StoreValue, ValueStore};
use lep2p::identity::Identity;
use lep2p::nat::{HelloEndpoint, NodeKeysEndpoint, ReflectEndpoint};
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

#[tokio::test(flavor = "multi_thread")]
async fn tampering_and_hijacking_are_rejected() {
    let (d_node, d_addr, d_store) = serve_node("signed-storage").await;
    let (a_node, _a_addr, _) = serve_node("signed-publisher").await;
    let (b_node, _b_addr, _) = serve_node("signed-reader").await;

    let a_to_d = a_node.connect(d_addr, d_node.node_id()).await.unwrap();
    let b_to_d = b_node.connect(d_addr, d_node.node_id()).await.unwrap();

    let a_dht = DhtNode::new(a_node.clone());
    let b_dht = DhtNode::new(b_node.clone());

    // Publisher stores a signed record.
    a_dht
        .put_signed(&a_to_d, "profile", "v1", 3600)
        .await
        .unwrap();

    // Reader verifies it against the expected publisher.
    let value = b_dht
        .get_signed(&b_to_d, "profile", Some(a_node.node_id()))
        .await
        .unwrap()
        .expect("record present");
    assert_eq!(value, b"v1");

    // Another node cannot hijack the key, neither signed…
    let err = b_dht
        .put_signed(&b_to_d, "profile", "hacked", 3600)
        .await
        .expect_err("hijack must be rejected");
    assert!(err.to_string().contains("owned"), "unexpected error: {err}");

    // …nor with an unsigned overwrite.
    let resp = b_to_d
        .request(
            "/v1/dht/put",
            json!({ "v": 1, "key": "profile", "ttl": 60, "value": "plain" }),
        )
        .await
        .unwrap();
    assert_eq!(resp["ok"], json!(false));

    // The storage node tampers with the stored value…
    {
        let mut store = d_store.write().unwrap();
        match store.get_mut("profile") {
            Some((StoreValue::Signed(record), _)) => record.value = "tampered".into(),
            _ => panic!("expected a signed record in the store"),
        }
    }
    // …and the reader detects it.
    let err = b_dht
        .get_signed(&b_to_d, "profile", Some(a_node.node_id()))
        .await
        .expect_err("tampering must be detected");
    assert!(
        err.to_string().contains("signature"),
        "unexpected error: {err}"
    );

    // A fresh key can be owned by another publisher and verified by a third node.
    b_dht
        .put_signed(&b_to_d, "b-profile", "bv", 3600)
        .await
        .unwrap();
    let value = a_dht
        .get_signed(&a_to_d, "b-profile", Some(b_node.node_id()))
        .await
        .unwrap()
        .expect("record present");
    assert_eq!(value, b"bv");
}

fn hash_id(seed: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(seed.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}
