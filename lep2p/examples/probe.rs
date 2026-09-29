//! Probe: connect to a node, verify its identity, run a control call.
//! Usage: lep2p-probe <addr:port> <expected_node_id_base32>

use lep2p::identity::{Identity, NodeId};
use lep2p::transport::NodeTransport;
use lep2p_core::Capabilities;
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let addr: std::net::SocketAddr = args.next().expect("addr").parse()?;
    let id_b32 = args.next().expect("node_id");
    let id_bytes = base32_decode(&id_b32).ok_or_else(|| anyhow::anyhow!("bad base32 node id"))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&id_bytes);
    let expected = NodeId(arr);

    let sender = Identity::from_bytes(&[7u8; 32]);
    let node = NodeTransport::bind(
        sender,
        "0.0.0.0:0".parse()?,
        "0.0.0.0:0".parse()?,
        Capabilities::default(),
    )
    .await?;

    println!("connecting to {addr} expecting {}", expected.short());
    let peer = node.connect(addr, expected).await?;
    println!("connected; peer id={} observed={}", peer.node_id.short(), peer.observed);

    let reflect = peer
        .request("/v1/nat/reflect", json!({"v": 1}))
        .await?;
    println!("reflect response: {reflect}");
    Ok(())
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s)
}
