//! TOML configuration for the node.

use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Address the single QUIC port binds to.
    pub listen: SocketAddr,
    /// Public IP advertised for bootstrapping / hole punching (defaults to listen IP).
    pub publish: Option<IpAddr>,
    /// TXT DNS seed hosts, e.g. `_lep2p.example.org`.
    pub seeds: Vec<String>,
    /// Path to persist the ed25519 key (auto-created if missing).
    pub keyfile: Option<String>,
    /// Whether relay/TURN proxying is enabled (M2; default off).
    pub relay: RelayConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct RelayConfig {
    pub enabled: bool,
    pub methods: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 12345),
            publish: None,
            seeds: vec![],
            keyfile: None,
            relay: RelayConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&raw)?)
    }

    /// The address advertised outward, defaulting to the listen IP.
    pub fn publish(&self) -> SocketAddr {
        let ip = self.publish.unwrap_or_else(|| self.listen.ip().to_owned());
        SocketAddr::new(ip, self.listen.port())
    }
}
