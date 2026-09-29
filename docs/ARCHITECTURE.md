# LeP2P — Architecture & Engineering Notes

P2P network for NAT traversal. Read this before any implementation work.

## Goals / use cases
- System application adding a TUN interface (virtual network, all ports reachable).
- Cryptocoin projects (mitigate NAT problems).
- Online games.
- Single-port node design. One QUIC port covers transport, control, coordination, and NAT helpers — no separate STUN/TURN/control ports, no external dependencies.

## Core principles
- **Identity**: ed25519 keypair. `NodeId = SHA-256(ed25519_pubkey)` (32 bytes), base32 "onion"-style encoding.
- **Overlay addressing**: IPv6 ULA prefix `fd00::/8`; host part = first 16 bytes of SHA-256(pubkey). Property: **address == identity**. Verification = recompute hash(pubkey) and compare to claimed overlay address; mismatch → drop the peer.
- **E2EE**: standard TLS 1.3 over QUIC. Node's self-signed root certificate == identity; X25519 key in the cert for key agreement. No one on-path sees traffic content. Verification = validate cert chain up to the self-signed root == node's ed25519 pubkey, and check overlay IPv6 == hash(pubkey).
- **Equal roles**: NO bootstrap/seed/server privilege split. DNS seeds are just ordinary nodes; DNS merely serves a *list of known addresses* for initial entry. Any node can: listen on its port, be an entry point, act as rendezvous for hole punching, participate in DHT, advertise capabilities.
- **Transport**: ONE UDP socket / ONE port. QUIC (tokio + quinn) with:
  - HTTP/3 JSON = **control plane** (flexible RPC endpoints).
  - Raw QUIC bidi streams = **data plane** (tunnels/overlay packets), NOT JSON.

## Stack decisions (finalized)
| Concern | Choice |
|---|---|
| Language / runtime | Rust, tokio |
| QUIC | quinn (TLS 1.3) |
| Control protocol | HTTP/3 + JSON (our own endpoint set) |
| Data plane | raw QUIC bidi streams |
| E2EE | TLS 1.3, self-signed root = NodeId (standard path, h3-compatible) |
| Overlay IPv6 | ULA `fd00::/8`, host = hash(pubkey) |
| DHT | Kademlia over control plane |
| DNS seeds | TXT records (not A/AAAA) |
| NAT | hole punching (on by default) + reflect + relay trait (stub, off) |
| NAT punch layer | QUIC-level (Initial packets), control via JSON over existing conn |

## Workspace layout
```
lep2p/                        # facade crate: client + server API for embedding
├── Cargo.toml
├── OPENCODE.md
├── crates/
│   ├── lep2p-identity/   # ed25519 keys, NodeId, overlay IPv6, base32, TLS root
│   ├── lep2p-core/       # NodeInfo, capabilities, messages, schema version
│   ├── lep2p-transport/  # 1-port QUIC TLS1.3 + HTTP/3 JSON + raw bidi streams
│   ├── lep2p-nat/        # reflect, hole punch, relay trait (stub)
│   ├── lep2p-dht/        # Kademlia + TXT DNS seeds
│   ├── lep2p-overlay/    # TUN + OS routing (milestone 2)
│   ├── lep2p-node/       # server binary + CLI + TOML config
```

## Milestones
- **M1 (current)**: identity → transport (+E2EE+endpoints) → NAT (reflect + hole punch) → DHT + TXT seeds → node binary + CLI. Verify: two nodes reach E2EE over hole-punched QUIC on LAN.
- **M2**: `lep2p-overlay` TUN + OS routing over raw QUIC bidi streams. HTTP/3 JSON stays control-only.

---

## M1 detailed spec

### 1. Identity (`lep2p-identity`)
- `Identity`: ed25519 secret → `NodeId`.
- `NodeId`: 32 bytes `SHA-256(pubkey)`; `to_base32()` (no padding); `Display(short)` first 12 chars.
- `overlay_ipv6()`: `fd00::` + last 16 bytes of `SHA-256(pubkey)`.
- TLS root: self-signed cert, public key = node ed25519 pubkey (encoded as X.509 public key), so cert chain root == identity. `NodeId(x) == NodeId(cert_pubkey)` verifies `cert ↔ identity`.
- Provide `rustls` ClientConfig/ServerConfig builders with per-connection custom verifier.

### 2. Core types (`lep2p-core`)
- `SchemaVersion` const (e.g. `1`).
- `NodeInfo { overlay_ipv6, public_addr: Option<SocketAddr>, capabilities, schema_version }`.
- `Capabilities { nat: NatCaps, dht: bool, overlay: bool }`, `NatCaps { hole_punch: bool, relay: bool, methods: Vec<NatMethod> }`.
- `Error` enum (wire/transport/punch/dht/identity etc.), `Result<T>`.
- JSON serde types with stable field names; every request/response carries `v`.

### 3. Transport (`lep2p-transport`)
- Single UDP socket bound to configured port.
- quinn Server + Client on same socket (quinn `Endpoint` supports one socket; client endpoint reuses it via `Endpoint::new` with the bound socket).
- ALPNs:
  - `h3` for HTTP/3 control.
  - `lep2p-overlay` for raw bidi data streams (M2).
- HTTP/3 server via `h3` crate handling control requests; dispatcher maps path → handler.
- Raw bidi streams: separate accept loop for `lep2p-overlay` ALPN connections; expose `open_raw_bidi(peer)`.
- E2EE: quinn configured with our self-signed-root verifier; handshake authenticates peer (see identity).

### 4. Endpoints (HTTP/3 JSON, control plane)
All under `/v1/`. Request/response bodies JSON with `v` field.
- `POST /v1/ping` → hello + `capabilities`.
- `POST /v1/node/info` → `NodeInfo` (incl. observed addr).
- `POST /v1/hello` → register `node_id` → observed addr + signed E2EE key bundle.
- `POST /v1/node/keys` → verified E2EE key bundle of a known peer.
- `POST /v1/connect` → establish full logical channel (E2EE context), returns capabilities.
- `POST /v1/nat/reflect` → return caller's observed external `ip:port` (seen on the incoming datagram/QUIC connection).
- `POST /v1/nat/punch` `{ target }` → target relays punch request to `target`; returns target's observed endpoint + punch intent.
- `POST /v1/nat/punch_ack` `{ my_observed, self_intent }` → peer confirms readiness; both fire QUIC Initials at each other's public endpoints.
- `POST /v1/dht/find_node` `{ target_id }` → `{ nodes: [...] }`.
- `POST /v1/dht/put` `{ key, value, ttl }`.
- `POST /v1/dht/get` `{ key }` → `{ value, nodes }`.
- `POST /v1/relay/offer` `{ target }` → relay address (stub; relay off by default).
- `POST /v1/relay/blob` `{ to, from_bundle, blob }` → queue a sealed blob for another node.
- `POST /v1/relay/pull` → drain sealed blobs addressed to the authenticated caller.

Capability advertisement: `ping`/`connect` respond with `capabilities` so the caller can pick a route (`nat.methods`).

### 5. NAT (`lep2p-nat`)
- **Reflect**: derive external `ip:port` from the QUIC connection's `RemoteAddress()` of the incoming datagram; serve via `nat/reflect`. Built into the same port (our own STUN analog).
- **Hole punch (on by default)**: peer A requests relay via rendezvous node R: `nat/punch { target: B }`. R forwards to B, gets B's observed endpoint + intent (`punch_ack`), returns to A. A and B simultaneously open NEW QUIC connections (Initials) to each other's observed public endpoints → NAT mapping opens → direct QUIC connection is established under HTTP/3. Control stays on the existing JSON connection to R; the punch itself is raw QUIC-level.
- **Relay/TURN**: defined as a pluggable trait; M1 = stub, off. M2 = proxy implementation.
- All nodes equal: any connected node can serve as rendezvous R (no privileged role).

### 6. DHT + DNS seeds (`lep2p-dht`)
- Kademlia over control plane. Join, `FIND_NODE`, `PUT`/`GET`, bucket refresh.
- **DNS seeds = list of ordinary nodes** (equal roles). TXT records:
  - One TXT record = one node contact, versioned string:
    `lep2p1|<pubkey_base32>|<overlay_ipv6>|<pub_port>|<ext_addr>`
  - Seed host can return multiple TXT records (node list) for redundancy.
  - Not A/AAAA; the in-network IPv6 + pubkey live in TXT specifically.
- Bootstrap flow:
  1. Resolve `_lep2p.<seed-host>` TXT → parse → candidate contact list.
  2. **Verify each**: overlay IPv6 must == hash(pubkey); drop failures (protects against spoofed seed DNS).
  3. Connect E2EE to any known node → enter network → find the rest via DHT.

### 7. Node binary + CLI (`lep2p-node`)
- `lep2p-node --seed seeds.conf`:
  - load-or-generate persistent keypair (ed25519), store to disk.
  - bind 1 port, quinn endpoint, HTTP/3 server.
  - bootstrap via TXT seeds → DHT join.
  - advertise capabilities, serve transport+endpoints.
- TOML config: `port`, `seeds = ["_lep2p.example.org"]`, `relay.enabled`, `relay.methods`, `limits` (conns, streams, payload), `persist.key` path.
- CLI extras: `--genkey`, `--print-identity` (NodeId + overlay IPv6), `--listen <port>`.

---

## M2 (in progress)
- **M2.1 (done)**: data plane — raw QUIC bidi streams (ALPN `lep2p-overlay`) carrying length-prefixed packets. `NodeTransport::connect_data` / `serve_with` with ALPN dispatch on the single endpoint; `DataConn` / `DataStream`; peer identity from mutual TLS.
- **M2.2 (next)**: `lep2p-overlay` — create TUN device via `tun` crate; forward mesh packets node→node through the data plane. OS routing handles the virtual network (transparent for games/crypto). HTTP/3 JSON remains control-only.
- **M2.3**: relay data plane — indirect paths with end-to-end encryption between endpoints.
- Relay proxy implementation for the relay trait.

## Conventions
- Rust, `edition 2021`.
- No comments unless they explain non-obvious crypto/network semantics.
- Workspace: `[workspace]` in root `Cargo.toml`, members listed.
- Re-export public API from `lep2p` facade crate.
- Verify: `cargo build`, `cargo clippy`, then a LAN two-node handshake test.
