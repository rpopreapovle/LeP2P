# Security model

## What is protected today

- **Per-hop transport**: every QUIC connection uses TLS 1.3 with **mutual**
  authentication. Each node's self-signed root certificate *is* its identity,
  the connecting side pins the expected `NodeId` (`SHA-256(ed25519 pubkey)`),
  and the accepting side requests and records the client certificate. On-path
  observers cannot read or modify traffic, and neither side can impersonate
  another node. The authenticated client identity is exposed to endpoint
  handlers as `CallCtx::peer_node_id`; `/v1/hello` rejects any `node_id` that
  does not match the TLS certificate.
- **Wire obfuscation**: QUIC datagrams are XOR-whitened with a keyed keystream
  derived from the receiving node's identity (`lep2p-obfs`), hiding QUIC/TLS
  signatures from DPI.
- **Data plane**: raw bidi streams (ALPN `lep2p-overlay`) run over the same
  mutually authenticated TLS 1.3 connections, so per-hop confidentiality and
  integrity hold. End-to-end encryption for *relayed* overlay traffic is the
  M2.3 item below.
- **Identity binding**: the overlay IPv6 address is derived from the public
  key, so `address == identity`; mismatches cause the peer to be dropped.

## What intermediate nodes can see

A rendezvous/relay node terminates the transport connection it receives, so it
can see:

- which `NodeId`s connect to it and when;
- observed public `ip:port` pairs of its clients (this is inherent to NAT
  reflection / hole punching);
- the *plaintext* of control-plane JSON messages that clients send **to it**
  (e.g. a punch request naming a target node).

It cannot see the contents of direct peer-to-peer QUIC connections, and it
cannot impersonate either side (TLS identity pinning).

## Application-layer E2EE (`lep2p-e2ee`)

To keep payloads private even when they pass through other nodes (rendezvous,
DHT forwarding, and later the relay/TURN path and the M2 overlay data plane),
the workspace provides `lep2p-e2ee`:

- **Static key agreement**: each node derives an X25519 key deterministically
  from its ed25519 identity (standard
  `crypto_sign_ed25519_sk_to_curve25519` construction). The public half is
  `to_montgomery(ed25519 pubkey)`. Peers combine their secret with the other
  side's public key; both compute the same secret.
- **Key schedule**: X25519 output goes through HKDF-SHA256 with a fixed salt
  (`lep2p-e2ee-v1-kdf`) and info (`lep2p-e2ee-v1-session`).
- **Key distribution**: `KeyBundle` is a self-verifying, signed binding between
  a node's ed25519 identity and its X25519 key. Bundles can be published
  through untrusted intermediaries (`/v1/hello`, `/v1/node/keys`) because a
  substituted bundle fails signature and `NodeId` checks.
- **AEAD**: payloads are sealed with ChaCha20-Poly1305; the associated data
  binds the message to the sender and receiver (`context_aad`), preventing
  cross-session replay. Relay blobs and sealed DHT records use
  **authenticated sealed boxes**: `ephemeral_pub (32) || nonce (12) ||
  ciphertext`, where the key mixes the static-static DH (which authenticates
  the sender — only the sender or recipient can produce a box that opens) with
  an ephemeral-static DH (which gives **sender-side forward secrecy**: later
  compromise of the sender's static key does not expose previously sent
  payloads).
- **Sealed-blob relay**: `/v1/relay/blob` queues a sealed blob in the target's
  mailbox on any node; the target drains it with `/v1/relay/pull`. The relay
  forwards opaque bytes and cannot read or meaningfully modify them. Mailboxes
  are bounded (`RelayLimits`: per-blob size, per-target count, total queued
  bytes) and blobs expire after a TTL, so relays cannot be flooded into
  unbounded memory growth.
- **Sealed DHT records**: `/v1/dht/put` accepts a record sealed to the intended
  reader's `KeyBundle` (`DhtNode::put_sealed`); the storage node keeps only
  ciphertext. Readers fetch and open it with `DhtNode::get_sealed`. The
  publisher's bundle is checked against the TLS-authenticated sender.
- **Relayed tunnels**: when a peer is only reachable through a relay, every
  packet is sealed with `seal_authenticated` before leaving the sender and
  opened only by the recipient, so the relay forwards opaque blobs. Sender
  authenticity for relayed streams rests on the sealed-box static DH (only the
  two endpoints can produce or consume valid blobs); the relay can refuse,
  drop, or delay traffic but cannot read or alter it.
- **Signed DHT records**: plaintext records can be signed by their publisher
  (`DhtNode::put_signed`); readers fetch them with `DhtNode::get_signed` and a
  required publisher, so a storage node cannot alter or swap values undetected.
  The first authenticated record under a key owns it: overwrites from other
  publishers and unsigned overwrites of owned keys are rejected.

Security properties: confidentiality and integrity against any node that is
not one of the two endpoints, including relays. Key compromise of one identity
does not expose other pairs (per-pair keys).

## Roadmap hardening

- Sender-side forward secrecy is implemented for sealed payloads (ephemeral
  X25519 mixed into the key schedule). The M2 data plane still needs a
  receiver-side ratchet for full forward secrecy.
- Seal relay offers and other coordination metadata with `lep2p-e2ee`
  (DHT values and relay blobs already support sealed modes; `find_node`
  addresses remain visible to the queried node by design).
- Mailbox quotas and TTLs are implemented (`RelayLimits`); request rate
  limiting and connection limits remain to bound other surfaces.
- Rate limiting and connection limits to mitigate DoS.
- Key rotation and revocation for long-lived identities.
