//! Real-TUN smoke test. Requires `CAP_NET_ADMIN` (root) and the kernel `tun`
//! module loaded (`sudo modprobe tun`).
//!
//! Run with:
//! `sudo -E cargo test -p lep2p --test overlay_tun -- --ignored`

use lep2p::identity::Identity;
use lep2p_overlay::{LinuxTun, OverlayNode};
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires CAP_NET_ADMIN and the kernel tun module"]
async fn creates_and_configures_a_tun_device() {
    let identity = Identity::from_bytes(&[42u8; 32]);
    let tun = LinuxTun::create("lep2p-test0", identity.overlay_ipv6(), 1420)
        .expect("create TUN device");
    assert_eq!(tun.name(), "lep2p-test0");

    // Attach an overlay node so the reader/writer halves are exercised.
    let node = OverlayNode::start(
        Arc::new(identity),
        Box::new(tun.reader()),
        Arc::new(tun.writer()),
    );
    assert_eq!(node.route_count(), 0);
}
