//! LeP2P facade: embeddable client + server API.
//!
//! Re-exports the identity, core, transport, NAT, DHT and overlay crates so that
//! embedding projects depend only on `lep2p`.

#![forbid(unsafe_code)]

pub use lep2p_core as core;
pub use lep2p_dht as dht;
pub use lep2p_e2ee as e2ee;
pub use lep2p_identity as identity;
pub use lep2p_nat as nat;
pub use lep2p_transport as transport;

#[cfg(feature = "overlay")]
pub use lep2p_overlay as overlay;
