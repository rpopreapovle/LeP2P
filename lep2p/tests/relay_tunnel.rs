//! M2.3 relay tunnel: packets tunnel through an intermediate node with
//! end-to-end encryption — the relay forwards only sealed blobs.

use lep2p::e2ee::KeyBundle;
use lep2p::identity::Identity;
use lep2p::transport::{DataConn, DataHandler, NodeTransport, Router};
use lep2p_core::{overlay_for, Capabilities};
use lep2p_overlay::{build_ipv6_packet, MemoryTun, OverlayNode};
use std::sync::Arc;
use std::time::Duration;

struct HandleInto {
    node: Arc<OverlayNode>,
}

#[async_trait::async_trait]
impl DataHandler for HandleInto {
    async fn on_data(&self, conn: DataConn) {
        self.node.handle_data(conn);
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

async fn wait<F: Fn() -> bool>(check: F) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn packets_tunnel_through_a_relay_with_e2ee() {
    let (r_transport, r_node, _r_tun) = overlay_node("relay-r").await;
    let (a_transport, a_node, a_tun) = overlay_node("relay-a").await;
    let (b_transport, b_node, b_tun) = overlay_node("relay-b").await;

    // The relay serves data-plane connections into its overlay node.
    let serve = r_transport.clone();
    let r_for_handler = r_node.clone();
    tokio::spawn(async move {
        let _ = serve
            .serve_with(
                Arc::new(Router::default()),
                Some(Arc::new(HandleInto {
                    node: r_for_handler,
                })),
            )
            .await;
    });

    // A and B connect to the relay; the relay registers them as data peers.
    let a_conn = a_transport
        .connect_data(r_transport.local_addr(), r_node.node_id())
        .await
        .expect("A data connect");
    let b_conn = b_transport
        .connect_data(r_transport.local_addr(), r_node.node_id())
        .await
        .expect("B data connect");
    assert!(
        wait(|| r_node.data_peer_count() == 2).await,
        "relay sees both peers"
    );

    // B accepts streams opened by the relay on its outgoing connection.
    b_node.handle_data(b_conn.clone());

    // A attaches B through the relay (key bundle known out of band here).
    let b_bundle = KeyBundle::create(&b_transport.identity());
    a_node
        .add_relayed_peer(a_conn.clone(), b_node.node_id(), b_bundle)
        .await
        .expect("relayed peering");

    let a_ip = overlay_for(&a_node.node_id());
    let b_ip = overlay_for(&b_node.node_id());
    assert!(
        wait(|| a_node.has_route(&b_ip)).await,
        "A has a route to B"
    );
    assert!(
        wait(|| b_node.has_route(&a_ip)).await,
        "B has a route to A"
    );

    // Packets tunnel both ways through the relay.
    let forward = build_ipv6_packet(a_ip, b_ip, b"through the relay");
    a_tun.inject(forward.clone());
    let delivered = b_tun
        .wait_packet(Duration::from_secs(2))
        .await
        .expect("B receives the relayed packet");
    assert_eq!(delivered, forward);

    let backward = build_ipv6_packet(b_ip, a_ip, b"back through the relay");
    b_tun.inject(backward.clone());
    let delivered = a_tun
        .wait_packet(Duration::from_secs(2))
        .await
        .expect("A receives the relayed packet");
    assert_eq!(delivered, backward);

    // The relay itself never registered overlay routes (it only forwards).
    assert_eq!(r_node.route_count(), 0);
    assert_eq!(a_node.route_count(), 1);
    assert_eq!(b_node.route_count(), 1);

    let _ = (a_conn, b_conn); // keep connections alive until the end
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_refuses_unknown_targets() {
    let (r_transport, r_node, _r_tun) = overlay_node("relay2-r").await;
    let (a_transport, a_node, _a_tun) = overlay_node("relay2-a").await;

    let serve = r_transport.clone();
    let r_for_handler = r_node.clone();
    tokio::spawn(async move {
        let _ = serve
            .serve_with(
                Arc::new(Router::default()),
                Some(Arc::new(HandleInto {
                    node: r_for_handler,
                })),
            )
            .await;
    });

    let a_conn = a_transport
        .connect_data(r_transport.local_addr(), r_node.node_id())
        .await
        .unwrap();
    assert!(wait(|| r_node.data_peer_count() == 1).await);

    let stranger = Identity::from_bytes(&hash_id("stranger"));
    let bundle = KeyBundle::create(&stranger);
    let err = a_node
        .add_relayed_peer(a_conn, stranger.node_id(), bundle)
        .await
        .expect_err("offline target must be refused");
    assert!(
        err.to_string().contains("target offline"),
        "unexpected error: {err}"
    );
}

fn hash_id(seed: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(seed.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}
