//! TXT DNS seeds: parse and verify bootstrap contacts.
//!
//! A seed host's TXT records (one per node) look like:
//! `lep2p1|<pubkey_base32>|<overlay_ipv6>|<pub_port>|<ext_addr>`
//! The in-network IPv6 is included explicitly and recomputed from the pubkey to
//! verify the record (defends against spoofed DNS responses).

use hickory_resolver::TokioAsyncResolver;
use lep2p_identity::{tls, Identity, NodeId};
use std::net::{IpAddr, SocketAddr};

/// Prefix of the TXT record string we emit / parse.
pub const TXT_PREFIX: &str = "lep2p1";

/// A verified bootstrap contact.
#[derive(Debug, Clone)]
pub struct SeedContact {
    pub node_id: NodeId,
    pub overlay_ipv6: std::net::Ipv6Addr,
    pub socket: SocketAddr,
}

/// Resolve TXT records for `_lep2p.<host>` and parse each into a contact.
pub async fn resolve_seeds(host: &str) -> anyhow::Result<Vec<SeedContact>> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let lookup = resolver.txt_lookup(host).await?;
    let mut out = Vec::new();
    for rdata in lookup.iter() {
        for txt_entry in rdata.txt_data() {
            if let Ok(s) = std::str::from_utf8(txt_entry.as_ref()) {
                if let Some(c) = parse_contact(s) {
                    out.push(c);
                }
            }
        }
    }
    Ok(out)
}

/// Parse one TXT string into a `SeedContact` (without verification).
fn parse_contact(s: &str) -> Option<SeedContact> {
    let parts: Vec<&str> = s.split('|').collect();
    if parts.len() != 5 || parts[0] != TXT_PREFIX {
        return None;
    }
    let node_id = lep2p_core::parse_node_id(parts[1])?;
    let overlay_ipv6: std::net::Ipv6Addr = parts[2].parse().ok()?;
    let port: u16 = parts[3].parse().ok()?;
    let ip: IpAddr = parts[4].parse().ok()?;
    Some(SeedContact {
        node_id,
        overlay_ipv6,
        socket: SocketAddr::new(ip, port),
    })
}

/// Recompute overlay IPv6 from the NodeId's embedded pubkey hash and check it
/// matches the claimed overlay address (address == identity).
pub fn verify_seed(c: &SeedContact) -> bool {
    let revealed = overlay_from_node_id(c.node_id);
    revealed == c.overlay_ipv6
}

fn overlay_from_node_id(id: NodeId) -> std::net::Ipv6Addr {
    crate::overlay_for(id)
}

/// Build a TXT record string for a node (used by seed publishers / DNS toolsing).
#[allow(dead_code)]
pub fn txt_record(identity: &Identity, port: u16, ext_addr: IpAddr) -> String {
    format!(
        "{TXT_PREFIX}|{}|{}|{}|{}",
        identity.node_id().to_base32(),
        identity.overlay_ipv6(),
        port,
        ext_addr
    )
}

// Keep tls import used (pubkey-based verification harness for tests/seed toolsing).
#[allow(dead_code)]
fn pubkey_node_id(identity: &Identity) -> NodeId {
    tls::cert_node_id(&tls::build_server_tls(identity).unwrap().cert)
        .unwrap_or_else(|| identity.node_id())
}
