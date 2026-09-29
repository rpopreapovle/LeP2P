//! LeP2P node: single-port QUIC node with HTTP/3 control plane, NAT traversal,
//! DHT, and TXT DNS seed bootstrap. Runs as a standalone daemon.

mod config;

use anyhow::Context;
use clap::Parser;
use config::Config;
use lep2p_core::{Capabilities, PingReq, PingResp, SCHEMA_VERSION};
use lep2p_dht::{DhtNode, FindNodeEndpoint, GetEndpoint, PutEndpoint};
use lep2p_identity::Identity;
use lep2p_nat::{
    HelloEndpoint, NodeKeysEndpoint, NoRelay, PunchEndpoint, ReflectEndpoint, RelayBlobEndpoint,
    RelayEndpoint, RelayPullEndpoint, RelayQueues,
};
use lep2p_transport::{CallCtx, Endpoint, EndpointResult, NodeTransport, PeerTable, Router};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

/// CLI entrypoint.
#[derive(Parser, Debug)]
#[command(name = "lep2p-node", about = "LeP2P single-port P2P node")]
struct Cli {
    /// Path to a TOML config file.
    #[arg(long)]
    config: Option<String>,
    /// Generate a fresh identity key to PATH and exit.
    #[arg(long, value_name = "PATH")]
    genkey: Option<String>,
    /// Load an identity key from PATH (used with --print-identity).
    #[arg(long, value_name = "PATH")]
    key: Option<String>,
    /// Print this node's identity (NodeId + overlay IPv6) and exit.
    #[arg(long)]
    print_identity: bool,
    /// Listen address override (host:port). Defaults to config.
    #[arg(long, value_name = "SOCKET")]
    listen: Option<SocketAddr>,
    /// Comma-separated TXT seed hosts, e.g. `_lep2p.example.org`.
    #[arg(long, value_name = "HOSTS")]
    seed: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,lep2p=debug".into()),
        )
        .init();

    let cli = Cli::parse();

    let mut cfg = match &cli.config {
        Some(p) => Config::load(p).context("load config")?,
        None => Config::default(),
    };
    if let Some(l) = cli.listen {
        cfg.listen = l;
    }
    if let Some(s) = cli.seed {
        cfg.seeds = s.split(',').map(str::trim).map(str::to_string).collect();
    }
    if let Some(k) = &cli.key {
        cfg.keyfile = Some(k.clone());
    }

    // Identity: generate a fresh key, or load/persist one from disk.
    if let Some(path) = &cli.genkey {
        let identity = Identity::generate();
        persist_identity(&identity, path)?;
        println!("wrote key to {}", path);
        return Ok(());
    }

    let identity = match &cfg.keyfile {
        Some(path) if std::path::Path::new(path).exists() => {
            load_identity(path).context("load identity")?
        }
        other => {
            let identity = Identity::generate();
            if let Some(path) = other {
                persist_identity(&identity, path)?;
            }
            identity
        }
    };

    if cli.print_identity {
        let identity = if let Some(path) = &cli.key {
            load_identity(path).context("load identity from --key")?
        } else {
            identity
        };
        print_identity(&identity);
        return Ok(());
    }

    run(identity, cfg).await
}

fn print_identity(identity: &Identity) {
    println!("node_id:     {}", identity.node_id().to_base32());
    println!("overlay ipv6: {}", identity.overlay_ipv6());
    println!("node_id short: {}", identity.node_id());
}

async fn run(identity: Identity, cfg: Config) -> anyhow::Result<()> {
    let node_id = identity.node_id();
    let caps = Capabilities {
        nat: lep2p_nat::default_nat_caps(),
        ..Capabilities::default()
    };

    // The external/publish address: use the configured listen address for LAN/direct.
    let transport = Arc::new(
        NodeTransport::bind(identity, cfg.listen, cfg.publish(), caps)
            .await
            .context("bind transport")?,
    );
    tracing::info!("node {} listening on {}", node_id.short(), transport.local_addr());

    // Shared state.
    let dht = Arc::new(DhtNode::new(transport.clone()));
    dht.table.write().unwrap().set_self(node_id);
    let peers: Arc<PeerTable> = dht.peers.clone();
    let store = dht.store.clone();

    // Wire the control endpoints.
    let relay_queues = RelayQueues::default();
    let router = Arc::new(Router::default());
    router.register("/v1/ping", PingEndpoint);
    router.register("/v1/node/info", InfoEndpoint);
    router.register("/v1/hello", HelloEndpoint::new(peers.clone()));
    router.register("/v1/node/keys", NodeKeysEndpoint::new(peers.clone()));
    router.register(
        "/v1/relay/blob",
        RelayBlobEndpoint::new(peers.clone(), relay_queues.clone()),
    );
    router.register(
        "/v1/relay/pull",
        RelayPullEndpoint::new(relay_queues.clone()),
    );
    router.register("/v1/nat/reflect", ReflectEndpoint);
    router.register(
        "/v1/nat/punch",
        PunchEndpoint::new(peers.clone()),
    );
    router.register(
        "/v1/relay/offer",
        RelayEndpoint::new(Arc::new(NoRelay)),
    );
    router.register(
        "/v1/dht/find_node",
        FindNodeEndpoint::new(peers.clone(), dht.table.clone()),
    );
    router.register("/v1/dht/put", PutEndpoint::new(store.clone()));
    router.register("/v1/dht/get", GetEndpoint::new(store.clone()));

    // Bootstrap from TXT DNS seeds (best effort; continue regardless).
    let boot = dht.bootstrap(&cfg.seeds).await?;
    tracing::info!("bootstrapped with {} seed peer(s)", boot.len());
    for p in &boot {
        tracing::debug!("seed peer: {} @ {}", p.node_id.short(), p.observed);
    }

    // Application side of the sealed-blob mailbox: drain blobs addressed to
    // this node and open them end-to-end.
    {
        let identity = transport.identity();
        let queues = relay_queues.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                for blob in queues.drain(&identity.node_id()) {
                    let from_id = lep2p_core::parse_node_id(&blob.from);
                    let opened = from_id.and_then(|from_id| {
                        if !blob.from_bundle.verify(&from_id) {
                            return None;
                        }
                        let key = blob.from_bundle.shared_key_with(&identity)?;
                        let aad = lep2p_e2ee::context_aad(&from_id, &identity.node_id());
                        lep2p_e2ee::open(&key, &aad, &blob.blob).ok()
                    });
                    match (from_id, opened) {
                        (_, Some(plain)) => tracing::info!(
                            "sealed message from {}: {}",
                            from_id.map(|n| n.short()).unwrap_or_default(),
                            String::from_utf8_lossy(&plain)
                        ),
                        (Some(from_id), None) => {
                            tracing::warn!("could not open relayed blob from {}", from_id.short())
                        }
                        (None, _) => tracing::warn!("bad sender id in relayed blob"),
                    }
                }
            }
        });
    }

    // Serve control plane forever.
    transport.clone().serve_control(router).await
}

// ---------------------------------------------------------------------------
// Builtin endpoints
// ---------------------------------------------------------------------------

struct PingEndpoint;
#[async_trait::async_trait]
impl Endpoint for PingEndpoint {
    async fn call(&self, ctx: &CallCtx, body: serde_json::Value) -> EndpointResult {
        let _req: PingReq = lep2p_transport::router::decode(body)?;
        use lep2p_transport::router::ok;
        ok(PingResp {
            v: SCHEMA_VERSION,
            node_id: ctx.identity.node_id().to_base32(),
            capabilities: ctx.capabilities.clone(),
        })
    }
}

struct InfoEndpoint;
#[async_trait::async_trait]
impl Endpoint for InfoEndpoint {
    async fn call(&self, ctx: &CallCtx, _body: serde_json::Value) -> EndpointResult {
        use lep2p_transport::router::ok;
        ok(json!({ "v": SCHEMA_VERSION, "node": ctx.node_info() }))
    }
}

// ---------------------------------------------------------------------------
// Identity persistence
// ---------------------------------------------------------------------------

fn persist_identity(identity: &Identity, path: &str) -> anyhow::Result<()> {
    let bytes = identity.to_bytes();
    std::fs::create_dir_all(
        std::path::Path::new(path)
            .parent()
            .unwrap_or(std::path::Path::new(".")),
    )?;
    std::fs::write(path, bytes)?;
    Ok(())
}

fn load_identity(path: &str) -> anyhow::Result<Identity> {
    let bytes = std::fs::read(path)?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!("identity file must be exactly 32 bytes (ed25519 secret)")
    })?;
    Ok(Identity::from_bytes(&arr))
}
