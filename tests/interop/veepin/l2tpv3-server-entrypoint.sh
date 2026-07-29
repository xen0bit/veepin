#!/bin/sh
# veepin L2TPv3 server: the end that binds and waits.
#
# A static pseudowire is symmetric, so "server" means only that this end does not
# dial. It learns the peer's address from the first packet that passes the cookie
# check -- never from an unverified one, which would let anyone redirect the
# tunnel.
set -u

: "${LOCAL_SESSION:?}"
: "${PEER_SESSION:?}"
: "${TUN_IP:?}"
UDP_PORT="${UDP_PORT:-1701}"
COOKIE="${COOKIE:-}"
PEER_COOKIE="${PEER_COOKIE:-}"
SHAPE="${SHAPE:-0}"

set -- \
    -listen 0.0.0.0 \
    -port "$UDP_PORT" \
    -session-id "$LOCAL_SESSION" \
    -peer-session-id "$PEER_SESSION" \
    -tun tap0 \
    -sublayer \
    -shape "$SHAPE"
[ -n "$COOKIE" ] && set -- "$@" -cookie "$COOKIE"
[ -n "$PEER_COOKIE" ] && set -- "$@" -peer-cookie "$PEER_COOKIE"

echo "veepin-l2tpv3-server: listening on :$UDP_PORT, session $LOCAL_SESSION <- -> $PEER_SESSION"
veepin serve l2tpv3 "$@" &
VEEPIN_PID=$!

for _ in $(seq 1 50); do
    if ip link show tap0 >/dev/null 2>&1; then break; fi
    sleep 0.2
done
if ! ip link show tap0 >/dev/null 2>&1; then
    echo "veepin-l2tpv3-server: tap0 never appeared" >&2
    exit 1
fi

ip link set tap0 up
ip addr add "$TUN_IP/24" dev tap0
echo "veepin-l2tpv3-server: tap0 = $TUN_IP"

iperf3 -s -1 >/dev/null 2>&1 &
wait $VEEPIN_PID
