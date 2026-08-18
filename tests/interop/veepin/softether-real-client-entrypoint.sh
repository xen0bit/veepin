#!/bin/sh
# veepin SoftEther client against a real SoftEther VPN Server.
#
# The cell the README's `‡` footnote has owed since the SoftEther row landed.
# Everything it proves is something the veepin<->veepin cell could not: the
# PACK codec's byte order, the three string encodings, the SHA-0 password
# construction, the HTTP layer the control plane rides on, and the block
# framing of the data path. Two veepin endpoints agree with each other about
# all five whether or not any of them is right.
#
# Addressing is static rather than DHCP. SecureNAT does run a DHCP server, but
# veepin has no DHCP client -- the segment is layer 2 and addressing inside it
# is the caller's business, which is exactly what internal/softether/README.md
# says. 192.168.30.5 sits below SecureNAT's default 192.168.30.10-200 pool, so
# nothing else will be handed it.
set -u

: "${SERVER:?}"
: "${USER:?}"
: "${PASSWORD:?}"
TUN_IP="${TUN_IP:-192.168.30.5}"
PEER_IP="${PEER_IP:-192.168.30.1}"
PORT="${PORT:-443}"
HUB="${HUB:-DEFAULT}"

# Docker's embedded DNS answers "server misbehaving" for a moment after a
# container starts, and Dial rightly treats an unresolvable server as an error
# rather than retrying forever.
for _ in $(seq 1 60); do
    if getent hosts "$SERVER" >/dev/null 2>&1; then break; fi
    sleep 0.5
done
if ! getent hosts "$SERVER" >/dev/null 2>&1; then
    echo "veepin-softether-client: $SERVER never resolved" >&2
    exit 1
fi

echo "veepin-softether-client: connecting to $SERVER:$PORT (hub $HUB)"
veepin connect softether \
    -server "$SERVER" \
    -port "$PORT" \
    -user "$USER" \
    -pass "$PASSWORD" \
    -hub "$HUB" \
    -insecure \
    -tun tap0 \
    -no-route \
    -retry-max 30 &
VEEPIN_PID=$!

for _ in $(seq 1 50); do
    if ip link show tap0 >/dev/null 2>&1; then break; fi
    sleep 0.2
done
if ! ip link show tap0 >/dev/null 2>&1; then
    echo "veepin-softether-client: tap0 never appeared" >&2
    exit 1
fi

ip link set tap0 up
ip addr add "$TUN_IP/24" dev tap0
echo "veepin-softether-client: tap0 = $TUN_IP"

# The ping's first packet is an ARP for the gateway, which is the exchange that
# has to cross a real SoftEther's switch and come back. Give the session a
# moment to be fully in tunnelling mode first.
sleep 3
if ping -c 5 -W 5 "$PEER_IP"; then
    echo "veepin-softether-client: PING OK"
else
    echo "veepin-softether-client: PING FAILED" >&2
    kill $VEEPIN_PID 2>/dev/null
    exit 1
fi

iperf3 -s -1 >/dev/null 2>&1 &
wait $VEEPIN_PID
