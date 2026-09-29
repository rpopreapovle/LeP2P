# LeP2P

A peer-to-peer networking library and node for NAT traversal, built on QUIC
with a single-port design. One UDP socket serves the QUIC transport, the
HTTP/3 control plane, NAT reflection, and hole punching — no separate
STUN/TURN/control ports and no external services required.

## Features

- **Single-port node**: one QUIC endpoint carries transport, control, and
  coordination traffic.
- **Identity = address**: ed25519 keypair; `NodeId = SHA-256(pubkey)`. Overlay
  IPv6 addresses live in the ULA range `fd00::/8` with the host part derived
  from the public key, so an address can be verified against its owner.
- **End-to-end encryption**: TLS 1.3 over QUIC. The node's self-signed root
  certificate is its identity; peers verify the certificate chain and the
  overlay address binding. Payloads that traverse intermediate nodes
  (rendezvous, relay) are additionally sealed with `lep2p-e2ee`
  (X25519 + ChaCha20-Poly1305), so relays see only opaque blobs.
- **Equal roles**: no privileged bootstrap/seed servers. DNS seeds are
  ordinary nodes publishing TXT records; any node can listen, rendezvous, or
  route.
- **NAT traversal**: binding reflection (built-in STUN analog) and UDP hole
  punching via a rendezvous peer, plus a pluggable relay/TURN trait (stub).
- **Kademlia DHT** over the control plane for peer discovery.

## Layout

```
lep2p/                        # facade crate: embeddable client + server API
crates/
  lep2p-identity/             # ed25519 keys, NodeId, overlay IPv6, TLS root
  lep2p-core/                 # NodeInfo, capabilities, messages, schema version
  lep2p-transport/            # 1-port QUIC TLS1.3 + HTTP/3 JSON control plane
  lep2p-nat/                  # reflect, hole punch, relay trait (stub)
  lep2p-dht/                  # Kademlia + TXT DNS seeds
  lep2p-obfs/                 # wire obfuscation of QUIC datagrams
  lep2p-e2ee/                 # application-layer end-to-end encryption
  lep2p-overlay/              # TUN + OS routing (milestone 2)
  lep2p-node/                 # server binary + CLI + TOML config
docs/ARCHITECTURE.md          # design notes and milestone spec
docs/SECURITY.md              # threat model and E2EE design
```

## Building

Requires a recent Rust toolchain (edition 2021).

```sh
cargo build --release
```

## Running a node

```sh
# Generate an identity key
./target/release/lep2p-node --genkey node.key

# Print the node identity (NodeId + overlay IPv6)
./target/release/lep2p-node --key node.key --print-identity

# Run the node (defaults: 0.0.0.0:12345, no seeds)
./target/release/lep2p-node --config lep2p-node.toml
```

Configuration is TOML (see `lep2p-node.toml.example`):

```toml
listen = "0.0.0.0:12345"
keyfile = "node.key"
seeds = ["_lep2p.example.org"]
relay = { enabled = false, methods = [] }
```

## Control plane

All endpoints are HTTP/3 JSON under `/v1/`; every message carries a `v`
(schema version) field.

| Endpoint | Description |
|---|---|
| `POST /v1/ping` | Hello + capabilities |
| `POST /v1/node/info` | NodeInfo (incl. observed address) |
| `POST /v1/hello` | Register node_id -> observed address (rendezvous) |
| `POST /v1/nat/reflect` | Caller's observed external `ip:port` |
| `POST /v1/nat/punch` | Hole punch toward a target via this rendezvous |
| `POST /v1/relay/offer` | Relay address (stub; relay off by default) |
| `POST /v1/dht/find_node` | Kademlia FIND_NODE |
| `POST /v1/dht/put` | DHT PUT |
| `POST /v1/dht/get` | DHT GET |

## Testing

```sh
cargo test
```

The end-to-end test (`lep2p/tests/slice.rs`) wires three nodes on loopback:
rendezvous, hole punch, and DHT `find_node`.

## License

GPLv3 or later. See [LICENSE](LICENSE).
