//! M2.1 data plane: framed packets over raw QUIC bidi streams (ALPN
//! `lep2p-overlay`), while HTTP/3 control stays on the same single port.

use lep2p::identity::{Identity, NodeId};
use lep2p::transport::*;
use lep2p_core::Capabilities;
use serde_json::json;
use std::sync::{Arc, Mutex};

/// Echoes every received packet back and records the authenticated peer.
///
/// Holds a handle per data connection (like a real application would), so
/// dropping the per-stream task does not implicitly close the connection.
struct Echo {
    peers: Arc<Mutex<Vec<NodeId>>>,
    conns: Arc<Mutex<Vec<DataConn>>>,
}

#[async_trait::async_trait]
impl DataHandler for Echo {
    async fn on_data(&self, conn: DataConn) {
        if let Some(peer) = conn.peer_node_id() {
            self.peers.lock().unwrap().push(peer);
        }
        self.conns.lock().unwrap().push(conn.clone());
        tokio::spawn(async move {
            let Ok(mut stream) = conn.accept_stream().await else {
                return;
            };
            loop {
                match stream.recv_packet().await {
                    Ok(Some(packet)) => {
                        if stream.send_packet(&packet).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = stream.finish();
                        break;
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

async fn bind(seed: &str) -> Arc<NodeTransport> {
    Arc::new(
        NodeTransport::bind(
            Identity::from_bytes(&hash_id(seed)),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            Capabilities::default(),
        )
        .await
        .unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn packets_flow_over_raw_streams() {
    let server = bind("data-server").await;
    let peers_log = Arc::new(Mutex::new(Vec::new()));
    let conns_log = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(Router::default());

    let serve = server.clone();
    let log = peers_log.clone();
    let conns = conns_log.clone();
    tokio::spawn(async move {
        let _ = serve
            .serve_with(
                router,
                Some(Arc::new(Echo {
                    peers: log,
                    conns,
                })),
            )
            .await;
    });

    let client = bind("data-client").await;

    // Data-plane connection over ALPN `lep2p-overlay`.
    let data = client
        .connect_data(server.local_addr(), server.node_id())
        .await
        .expect("open data connection");
    let mut stream = data.open_stream().await.expect("open data stream");

    for i in 0..3u8 {
        let packet = format!("ping-{i}").into_bytes();
        stream.send_packet(&packet).await.unwrap();
        let echoed = stream.recv_packet().await.unwrap().expect("echo");
        assert_eq!(echoed, packet);
    }

    // A larger frame survives framing intact.
    let big = vec![0xABu8; 4096];
    stream.send_packet(&big).await.unwrap();
    assert_eq!(stream.recv_packet().await.unwrap().unwrap(), big);

    // Clean shutdown: finish() surfaces as `None` on the other side, and the
    // echo comes back as a clean end too.
    stream.finish().unwrap();
    assert!(stream.recv_packet().await.unwrap().is_none());

    // The server saw the TLS-authenticated client identity on the data plane.
    assert_eq!(*peers_log.lock().unwrap(), vec![client.node_id()]);

    // Control plane (HTTP/3) still works on the same endpoint and port.
    let control = client
        .connect(server.local_addr(), server.node_id())
        .await
        .expect("control connect");
    let resp = control
        .request("/v1/does-not-exist", json!({ "v": 1 }))
        .await
        .expect("control request");
    assert_eq!(resp["ok"], json!(false));
    assert_eq!(resp["error"], json!("not found"));

    // A client pinned to the wrong identity must not establish the data plane.
    // The rejection may surface only after quinn's idle timeout, so bound the
    // wait and treat both "rejected" and "never connected" as success.
    let wrong = Identity::from_bytes(&hash_id("someone-else"));
    let attempt = client.connect_data(server.local_addr(), wrong.node_id());
    match tokio::time::timeout(std::time::Duration::from_secs(2), attempt).await {
        Err(_) => {}
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("identity mismatch must not connect"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn data_plane_is_refused_when_disabled() {
    let server = bind("no-data-server").await;
    let serve = server.clone();
    tokio::spawn(async move {
        let _ = serve
            .serve_control(Arc::new(Router::default()))
            .await;
    });

    let client = bind("no-data-client").await;
    let data = client
        .connect_data(server.local_addr(), server.node_id())
        .await
        .expect("QUIC handshake succeeds");
    // The server closes the connection because no data handler is configured.
    let mut stream = data.open_stream().await.expect("stream opens locally");
    let result = stream.send_packet(b"hello").await;
    // Either the send or a subsequent receive must observe the close.
    let closed = result.is_err() || stream.recv_packet().await.is_err();
    assert!(closed, "disabled data plane must not serve packets");
}

fn hash_id(seed: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(seed.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}
