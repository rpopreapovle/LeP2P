#!/usr/bin/env bash
# Live end-to-end overlay test without root.
#
# Runs two lep2p-node daemons in separate network namespaces linked by a veth
# pair. Each daemon creates a real TUN device with its overlay IPv6 address,
# peers over QUIC through the veth, and a real `ping6` traverses the tunnel.
#
# Requires: Linux with unprivileged user namespaces, the kernel `tun` module
# loaded (`sudo modprobe tun`), and `ip`, `nsenter`, `ping`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/lep2p-node"
WORK="$(mktemp -d /tmp/lep2p-live.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

echo "building lep2p-node..."
cargo build --release -p lep2p-node --manifest-path "$ROOT/Cargo.toml" >/dev/null

"$BIN" --genkey "$WORK/a.key" >/dev/null
"$BIN" --genkey "$WORK/b.key" >/dev/null
A_ID=$("$BIN" --key "$WORK/a.key" --print-identity | awk '/^node_id:/{print $2}')
B_ID=$("$BIN" --key "$WORK/b.key" --print-identity | awk '/^node_id:/{print $2}')
A_V6=$("$BIN" --key "$WORK/a.key" --print-identity | awk '/^overlay/{print $3}')
B_V6=$("$BIN" --key "$WORK/b.key" --print-identity | awk '/^overlay/{print $3}')

cat > "$WORK/a.toml" <<EOF
listen = "0.0.0.0:12001"
keyfile = "$WORK/a.key"
seeds = []
overlay = { enabled = true, name = "ov-a", mtu = 1420, peers = ["$B_ID@10.9.0.2:12002"] }
EOF
cat > "$WORK/b.toml" <<EOF
listen = "0.0.0.0:12002"
keyfile = "$WORK/b.key"
seeds = []
overlay = { enabled = true, name = "ov-b", mtu = 1420, peers = [] }
EOF

cat > "$WORK/inner.sh" <<'INNER'
set -e
ip link set lo up

unshare -n sleep 600 & A_PID=$!
unshare -n sleep 600 & B_PID=$!
sleep 0.5

ip link add va type veth peer name vb
ip link set va netns "$A_PID"
ip link set vb netns "$B_PID"
nsenter -t "$A_PID" -n sh -c "ip link set lo up; ip link set va up; ip addr add 10.9.0.1/24 dev va"
nsenter -t "$B_PID" -n sh -c "ip link set lo up; ip link set vb up; ip addr add 10.9.0.2/24 dev vb"

nsenter -t "$A_PID" -n "$BIN" --config "$WORK/a.toml" >"$WORK/a.log" 2>&1 & DAEMON_A=$!
nsenter -t "$B_PID" -n "$BIN" --config "$WORK/b.toml" >"$WORK/b.log" 2>&1 & DAEMON_B=$!
sleep 2
for _ in $(seq 1 15); do
    grep -q "attached" "$WORK/a.log" && break
    sleep 1
done

nsenter -t "$A_PID" -n ip -6 route add "$B_V6"/128 dev ov-a
nsenter -t "$B_PID" -n ip -6 route add "$A_V6"/128 dev ov-b

nsenter -t "$A_PID" -n ping -6 -c 3 -W 2 "$B_V6"

kill "$DAEMON_A" "$DAEMON_B" "$A_PID" "$B_PID" 2>/dev/null || true
INNER

BIN="$BIN" WORK="$WORK" A_V6="$A_V6" B_V6="$B_V6" unshare -Urn bash "$WORK/inner.sh"
echo "live TUN test passed"
