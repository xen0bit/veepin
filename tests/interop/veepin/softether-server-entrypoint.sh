#!/bin/sh
# veepin SoftEther VPN server for the veepin<->veepin cell.
#
# SoftEther is layer 2: the server opens a TAP, puts it on its own switch as an
# ordinary bridge port, and switches Ethernet frames between it and the
# connected clients. It assigns no address to that TAP itself, so the harness
# does it here -- exactly as it does for l2tpv3, the other layer-2 protocol, and
# exactly as a real deployment would inside the bridged segment.
set -u

: "${USER:?}"
: "${PASSWORD:?}"
TUN_IP="${TUN_IP:-10.70.0.1}"
PORT="${PORT:-443}"

# A self-signed certificate: the client passes -insecure, since SoftEther ships
# a self-signed certificate by default and that is the configuration this cell
# reproduces.
mkdir -p /certs
if [ ! -f /certs/server.crt ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /certs/server.key -out /certs/server.crt \
        -days 2 -subj "/CN=veepin-softether-server" \
        -addext "subjectAltName=DNS:veepin-softether-server" >/dev/null 2>&1
fi

echo "veepin-softether-server: listening on :$PORT"
veepin serve softether \
    -listen 0.0.0.0 \
    -port "$PORT" \
    -cert /certs/server.crt \
    -key /certs/server.key \
    -user "$USER" \
    -pass "$PASSWORD" \
    -shape "${SHAPE:-0}" \
    -tun tap0 &
VEEPIN_PID=$!

for _ in $(seq 1 50); do
    if ip link show tap0 >/dev/null 2>&1; then break; fi
    sleep 0.2
done
if ! ip link show tap0 >/dev/null 2>&1; then
    echo "veepin-softether-server: tap0 never appeared" >&2
    exit 1
fi

ip link set tap0 up
ip addr add "$TUN_IP/24" dev tap0
echo "veepin-softether-server: tap0 = $TUN_IP"

iperf3 -s -1 >/dev/null 2>&1 &
wait $VEEPIN_PID
