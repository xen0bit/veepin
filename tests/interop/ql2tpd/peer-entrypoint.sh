#!/bin/sh
# ql2tpd as an L2TPv3 quiescent-tunnel peer: the kernel data plane plus HELLO
# keepalives over the RFC 3931 control connection.
#
# Cookie direction, again the thing worth reading twice. go-l2tp's config uses
# the same convention iproute2 does and the OPPOSITE names to RFC 3931's
# receiver-chooses framing:
#
#   cookie      -- included in packets ql2tpd SENDS   -> veepin's -cookie
#   peer_cookie -- expected on packets ql2tpd RECEIVES -> veepin's -peer-cookie
#
# tid/ptid are the Control Connection IDs, not the data Session IDs; L2TPv3
# keeps them separate and both ends must agree on both pairs.
set -eu

: "${PEER:?}"
: "${TID:?}"
: "${PTID:?}"
: "${LOCAL_SESSION:?}"
: "${PEER_SESSION:?}"
: "${TUN_IP:?}"
UDP_PORT="${UDP_PORT:-1701}"
HELLO_MS="${HELLO_MS:-3000}"

modprobe l2tp_eth 2>/dev/null || true
modprobe l2tp_netlink 2>/dev/null || true

for _ in $(seq 1 60); do
    if getent hosts "$PEER" >/dev/null 2>&1; then break; fi
    sleep 0.5
done
PEER_IP=$(getent hosts "$PEER" | awk '{print $1; exit}')
LOCAL_IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
if [ -z "$PEER_IP" ]; then
    echo "ql2tpd-peer: cannot resolve $PEER" >&2
    exit 1
fi

mkdir -p /etc/ql2tpd
cat > /etc/ql2tpd/ql2tpd.toml <<TOML
[tunnel.t1]
local = "${LOCAL_IP}:${UDP_PORT}"
peer = "${PEER_IP}:${UDP_PORT}"
version = "l2tpv3"
encap = "udp"
tid = ${TID}
ptid = ${PTID}
# hello_timeout is what switches ql2tpd from static into QUIESCENT mode: it
# brings up the control connection and starts exchanging HELLOs. Without it
# this peer sends no control messages at all and the cell would prove nothing.
hello_timeout = ${HELLO_MS}

[tunnel.t1.session.s1]
pseudowire = "eth"
sid = ${LOCAL_SESSION}
psid = ${PEER_SESSION}
interface_name = "l2tpeth0"
l2spec_type = "default"
TOML

echo "ql2tpd-peer: local=$LOCAL_IP peer=$PEER_IP tid=$TID ptid=$PTID hello=${HELLO_MS}ms"
cat /etc/ql2tpd/ql2tpd.toml

ql2tpd -config /etc/ql2tpd/ql2tpd.toml -verbose 2>&1 &
QL_PID=$!

for _ in $(seq 1 60); do
    if ip link show l2tpeth0 >/dev/null 2>&1; then break; fi
    sleep 0.5
done
if ! ip link show l2tpeth0 >/dev/null 2>&1; then
    echo "ql2tpd-peer: l2tpeth0 never appeared" >&2
    exit 1
fi

ip link set l2tpeth0 up
ip addr add "$TUN_IP/24" dev l2tpeth0
echo "ql2tpd-peer: pseudowire up, l2tpeth0 = $TUN_IP"

iperf3 -s -1 >/dev/null 2>&1 &
wait $QL_PID
