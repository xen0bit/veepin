#!/bin/sh
# veepin L2TPv3 client against the kernel's static pseudowire.
#
# The tunnel is layer 2: veepin brings up a TAP device and assigns NO address of
# its own (client.Result.Layer2). The address below is put on the interface here,
# by the harness, exactly as a real deployment would do with DHCP or a static
# assignment inside the bridged segment.
set -u

: "${PEER:?}"
: "${LOCAL_SESSION:?}"
: "${PEER_SESSION:?}"
: "${TUN_IP:?}"
UDP_PORT="${UDP_PORT:-1701}"
COOKIE="${COOKIE:-}"
PEER_COOKIE="${PEER_COOKIE:-}"
SHAPE="${SHAPE:-0}"
CCID="${CCID:-0}"
PEER_CCID="${PEER_CCID:-0}"
KEEPALIVE="${KEEPALIVE:-0}"

set -- \
    -gateway "$PEER" \
    -port "$UDP_PORT" \
    -session-id "$LOCAL_SESSION" \
    -peer-session-id "$PEER_SESSION" \
    -tun tap0 \
    -sublayer \
    -shape "$SHAPE" \
    -ccid "$CCID" \
    -peer-ccid "$PEER_CCID" \
    -keepalive "$KEEPALIVE"
[ -n "$COOKIE" ] && set -- "$@" -cookie "$COOKIE"
[ -n "$PEER_COOKIE" ] && set -- "$@" -peer-cookie "$PEER_COOKIE"

# Wait for the peer's name to resolve. Docker's embedded DNS answers with
# "server misbehaving" for a moment after a container starts, and Dial rightly
# treats an unresolvable gateway as an error rather than retrying forever.
for _ in $(seq 1 60); do
    if getent hosts "$PEER" >/dev/null 2>&1; then break; fi
    sleep 0.5
done
if ! getent hosts "$PEER" >/dev/null 2>&1; then
    echo "veepin-l2tpv3-client: $PEER never resolved" >&2
    exit 1
fi

echo "veepin-l2tpv3-client: connecting to $PEER:$UDP_PORT, session $LOCAL_SESSION <- -> $PEER_SESSION"
veepin connect l2tpv3 "$@" &
VEEPIN_PID=$!

# Wait for the TAP device, then address it from outside the tunnel.
for _ in $(seq 1 50); do
    if ip link show tap0 >/dev/null 2>&1; then break; fi
    sleep 0.2
done
if ! ip link show tap0 >/dev/null 2>&1; then
    echo "veepin-l2tpv3-client: tap0 never appeared" >&2
    exit 1
fi

ip link set tap0 up
ip addr add "$TUN_IP/24" dev tap0
echo "veepin-l2tpv3-client: tap0 = $TUN_IP"

iperf3 -s -1 >/dev/null 2>&1 &
wait $VEEPIN_PID
