#!/bin/sh
# veepin SoftEther VPN client for the veepin<->veepin cell.
#
# Layer 2 again: veepin brings up a TAP and assigns no address of its own
# (client.Result.Layer2), so the harness puts one on afterwards -- which is also
# how two clients get different addresses despite the server naming the same
# 10.70.0.2 to both, a caveat this cell exposes rather than papers over.
#
# The data-path check is a ping to the server's own TAP. That frame has to leave
# this TAP, cross TLS, be switched onto the server's local bridge port, and
# arrive on an interface the server's kernel answers for. A handshake that
# completes and moves no frame fails here, which is the point: for as long as
# this protocol has existed, that was exactly what happened -- neither end
# pumped frames at all.
set -u

: "${SERVER:?}"
: "${USER:?}"
: "${PASSWORD:?}"
: "${TUN_IP:?}"
PEER_IP="${PEER_IP:-10.70.0.1}"
PORT="${PORT:-443}"

# Docker's embedded DNS answers "server misbehaving" for a moment after a
# container starts, and Dial rightly treats an unresolvable server as an error
# rather than retrying forever.
#
# The listener coming up after us is handled by -retry rather than by a second
# wait loop here: that is what the reconnection loop is for, and a cell that
# exercises it is worth more than one that tiptoes around it. -retry-max bounds
# it, so a genuinely dead server fails the cell instead of hanging it.
for _ in $(seq 1 60); do
    if getent hosts "$SERVER" >/dev/null 2>&1; then break; fi
    sleep 0.5
done
if ! getent hosts "$SERVER" >/dev/null 2>&1; then
    echo "veepin-softether-client: $SERVER never resolved" >&2
    exit 1
fi

echo "veepin-softether-client: connecting to $SERVER:$PORT"
veepin connect softether \
    -server "$SERVER" \
    -port "$PORT" \
    -user "$USER" \
    -pass "$PASSWORD" \
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

# Give the switch a moment to learn our MAC from the ARP we are about to send.
sleep 2
if ping -c 5 -W 5 "$PEER_IP"; then
    echo "veepin-softether-client: PING OK"
else
    echo "veepin-softether-client: PING FAILED" >&2
    kill $VEEPIN_PID 2>/dev/null
    exit 1
fi

iperf3 -s -1 >/dev/null 2>&1 &
wait $VEEPIN_PID
