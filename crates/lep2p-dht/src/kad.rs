//! Minimal Kademlia routing: fixed-size buckets by XOR distance.

use lep2p_identity::NodeId;
use std::collections::HashMap;
use std::net::SocketAddr;

const ID_BITS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Distance(pub [u8; 32]);

impl Distance {
    /// XOR distance between two node ids.
    pub fn xor(a: &NodeId, b: &NodeId) -> Distance {
        let mut out = [0u8; 32];
        for (o, (x, y)) in out.iter_mut().zip(a.0.iter().zip(&b.0)) {
            *o = x ^ y;
        }
        Distance(out)
    }

    fn bucket_index(&self) -> usize {
        let mut prefix = 0usize;
        for byte in self.0 {
            if byte != 0 {
                return prefix + byte.leading_zeros() as usize;
            }
            prefix += 8;
        }
        ID_BITS
    }
}

#[derive(Debug, Clone)]
pub struct KadNode {
    pub id: NodeId,
    pub addr: SocketAddr,
}

const BUCKET_SIZE: usize = 16;

/// A k-bucket table keyed by leading-zero count of the XOR distance to self.
#[derive(Default)]
pub struct RoutingTable {
    self_id: Option<NodeId>,
    /// bucket index (0..=256) -> nodes known in that bucket
    buckets: HashMap<usize, Vec<KadNode>>,
}

impl RoutingTable {
    /// Record this node's own id so bucket placement is correct.
    pub fn set_self(&mut self, id: NodeId) {
        self.self_id = Some(id);
    }

    pub fn insert(&mut self, id: NodeId, addr: SocketAddr) {
        let bucket = match self.self_id {
            Some(own) if own != id => Distance::xor(&own, &id).bucket_index(),
            _ => 0,
        };
        let entries = self.buckets.entry(bucket).or_default();
        if !entries.iter().any(|n| n.id == id) {
            entries.push(KadNode { id, addr });
            if entries.len() > BUCKET_SIZE {
                entries.remove(0);
            }
        }
    }

    pub fn all(&self) -> Vec<(NodeId, SocketAddr)> {
        self.buckets
            .values()
            .flat_map(|v| v.iter().map(|n| (n.id, n.addr)))
            .collect()
    }
}
