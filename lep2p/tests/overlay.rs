//! M2.2 overlay: IP packets routed by overlay IPv6 address between two nodes
//! over the data plane, using in-memory TUN devices (no root required).

use lep2p::identity::Identity;
use lep2p::transport::{DataConn, DataHandler, NodeTransport, Router};
use lep2p_core::{overlay_for, Capabilities};
use lep2p_overlay::{build_ipv6_packet, MemoryTun, OverlayNode};
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;

/// Accepts incoming data connections into an overlay node.
struct AcceptInto {
    node: Arc<OverlayNode>,
}

#[async_trait::async_trait]
impl DataHandler for AcceptInto {
    async fn on_data(&self, conn: DataConn) {
        let node = self.node.clone();
        tokio::spawn(async move {
            let _ = node.accept_peer(conn).await;
        });
    }
}

async fn overlay_node(seed: &str) -> (Arc<NodeTransport>, Arc<OverlayNode>, MemoryTun) {
    let transport = Arc::new(
        NodeTransport::bind(
            Identity::from_bytes(&hash_id(seed)),
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
            Capabilities::default(),
        )
        .await
        .unwrap(),
    );
    let tun = MemoryTun::new();
    let node = OverlayNode::start(
        transport.identity(),
        Box::new(tun.reader()),
        Arc::new(tun.writer()),
    );
    (transport, node, tun)
}

async fn wait_route(node: &Arc<OverlayNode>, dst: &Ipv6Addr) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        if node.has_route(dst) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn packets_route_by_overlay_address() {
    let (a_transport, a_node, a_tun) = overlay_node("overlay-a").await;
    let (b_transport, b_node, b_tun) = overlay_node("overlay-b").await;

    // B serves the data plane into its overlay node.
    let serve = b_transport.clone();
    let b_for_handler = b_node.clone();
    tokio::spawn(async move {
        let _ = serve
            .serve_with(
                Arc::new(Router::default()),
                Some(Arc::new(AcceptInto {
                    node: b_for_handler,
                })),
            )
            .await;
    });

    // A attaches to B over the data plane.
    let conn = a_transport
        .connect_data(b_transport.local_addr(), b_node.node_id())
        .await
        .expect("data connect");
    a_node.add_peer(conn).await.expect("overlay peering");

    let a_ip = overlay_for(&a_node.node_id());
    let b_ip = overlay_for(&b_node.node_id());
    assert!(wait_route(&a_node, &b_ip).await, "A route to B");
    assert!(wait_route(&b_node, &a_ip).await, "B route to A");
    assert_eq!(a_node.route_count(), 1);
    assert_eq!(b_node.route_count(), 1);

    // A -> B.
    let forward = build_ipv6_packet(a_ip, b_ip, b"hello from A");
    a_tun.inject(forward.clone());
    let delivered = b_tun
        .wait_packet(Duration::from_secs(2))
        .await
        .expect("B receives the packet");
    assert_eq!(delivered, forward);

    // B -> A.
    let backward = build_ipv6_packet(b_ip, a_ip, b"hello from B");
    b_tun.inject(backward.clone());
    let delivered = a_tun
        .wait_packet(Duration::from_secs(2))
        .await
        .expect("A receives the packet");
    assert_eq!(delivered, backward);

    // Packets without a route are dropped, and malformed packets do not panic.
    let unknown = build_ipv6_packet(
        a_ip,
        "fd00:dead:beef::1".parse().unwrap(),
        b"nowhere",
    );
    a_tun.inject(unknown);
    a_tun.inject(vec![0x00, 0x01, 0x02]); // not IPv6
    assert!(
        b_tun.wait_packet(Duration::from_millis(300)).await.is_none(),
        "unrouted packets must not be delivered"
    );
    assert_eq!(a_node.route_count(), 1, "routes stay intact");
}

#[tokio::test(flavor = "multi_thread")]
async fn overlay_hello_rejects_address_mismatch() {
    let (attacker_transport, attacker_node, _attacker_tun) =
        overlay_node("overlay-attacker").await;
    let (b_transport, b_node, _b_tun) = overlay_node("overlay-victim").await;

    // B serves the data plane.
    let serve = b_transport.clone();
    let b_for_handler = b_node.clone();
    tokio::spawn(async move {
        let _ = serve
            .serve_with(
                Arc::new(Router::default()),
                Some(Arc::new(AcceptInto {
                    node: b_for_handler,
                })),
            )
            .await;
    });

    // The advertised overlay address is derived from the node id, so a hello
    // with a mismatching address must be rejected.
    let conn = attacker_transport
        .connect_data(b_transport.local_addr(), b_node.node_id())
        .await
        .unwrap();
    let mut stream = conn.open_stream().await.unwrap();
    let forged = serde_json::json!({
        "v": 1,
        "node_id": attacker_node.node_id().to_base32(),
        "overlay_ipv6": "fd00::1",
    });
    stream
        .send_packet(&serde_json::to_vec(&forged).unwrap())
        .await
        .unwrap();
    // B sends its hello first; drain it, then wait for the rejection.
    let _ = stream.recv_packet().await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        b_node.route_count(),
        0,
        "a hello with a mismatching overlay address must not register a route"
    );
}

fn hash_id(seed: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(seed.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}
