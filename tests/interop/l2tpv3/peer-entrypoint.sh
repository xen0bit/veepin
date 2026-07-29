#!/bin/sh
# Linux kernel L2TPv3 Ethernet pseudowire, configured statically with iproute2.
#
# The cookie direction is the thing this cell exists to check, so read the two
# `cookie` arguments carefully:
#
#   cookie      -- what WE put on packets we SEND (the peer verifies it)
#   peer_cookie -- what we EXPECT on packets we RECEIVE
#
# iproute2 names them from the sender's point of view, which is the opposite of
# how RFC 3931 describes the field (the RECEIVER chooses it). So veepin's
# -cookie (what veepin expects inbound) must equal the kernel's `cookie` here,
# and veepin's -peer-cookie must equal the kernel's `peer_cookie`. Getting that
# backwards is invisible in a veepin-to-veepin test and fatal here, which is
# exactly the point.
set -eu

: "${PEER:?PEER (the veepin container name) is required}"
: "${LOCAL_SESSION:?}"
: "${PEER_SESSION:?}"
: "${TUN_IP:?}"
UDP_PORT="${UDP_PORT:-1701}"
COOKIE="${COOKIE:-}"
PEER_COOKIE="${PEER_COOKIE:-}"

modprobe l2tp_eth 2>/dev/null || true
modprobe l2tp_netlink 2>/dev/null || true

if ! ip l2tp show tunnel >/dev/null 2>&1; then
    echo "l2tpv3-peer: FATAL: the kernel has no L2TP support (l2tp_netlink missing)" >&2
    exit 1
fi

PEER_IP=$(getent hosts "$PEER" | awk '{print $1; exit}')
if [ -z "$PEER_IP" ]; then
    echo "l2tpv3-peer: cannot resolve $PEER" >&2
    exit 1
fi
LOCAL_IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)

echo "l2tpv3-peer: local=$LOCAL_IP peer=$PEER_IP session $LOCAL_SESSION <- -> $PEER_SESSION"

ip l2tp add tunnel \
    tunnel_id 1 peer_tunnel_id 1 \
    encap udp local "$LOCAL_IP" remote "$PEER_IP" \
    udp_sport "$UDP_PORT" udp_dport "$UDP_PORT"

# shellcheck disable=SC2086
set -- session_id "$LOCAL_SESSION" peer_session_id "$PEER_SESSION"
[ -n "$COOKIE" ] && set -- "$@" cookie "$COOKIE"
[ -n "$PEER_COOKIE" ] && set -- "$@" peer_cookie "$PEER_COOKIE"

ip l2tp add session name l2tpeth0 tunnel_id 1 "$@"

ip link set l2tpeth0 up
ip addr add "$TUN_IP/24" dev l2tpeth0

echo "l2tpv3-peer: pseudowire up, l2tpeth0 = $TUN_IP"
ip l2tp show session

# The kernel side is entirely passive once configured; hold the container open
# and serve iperf3 for the throughput measurement.
iperf3 -s -1 >/dev/null 2>&1 &
exec sleep infinity
