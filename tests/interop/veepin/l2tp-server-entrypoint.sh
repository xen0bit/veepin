#!/bin/sh
# veepin L2TP/IPsec server for the interop harness. -setup-nat assigns the
# gateway address (pool .1 = 10.20.0.1) to the TUN so the kernel answers pings to
# it — the data-path assertion. No -wan, so no MASQUERADE is installed.
#
# SHAPE is the per-flow downstream shaping budget in bytes (0, the default, is
# off). A non-zero value pads the PPP Information field past the inner IP packet
# (RFC 1661 §5.1), which the peer must trim by the IP header's own length.
set -eu
SHAPE="${SHAPE:-0}"
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
# The IKE identity and phase-2 traffic selector must name the address clients
# reach, which compose assigns at run time — the wildcard the sockets bind cannot
# supply it.
PUBLIC="${PUBLIC:-$(ip -4 -o addr show scope global | awk 'NR==1 {split($4, a, "/"); print a[1]}')}"

echo "veepin-l2tp-server: serving l2tp on udp/500, public ${PUBLIC}, gateway 10.20.0.1, shape ${SHAPE}"
exec veepin serve l2tp \
    -public "$PUBLIC" \
    -psk "${PSK:-l2tpsecret}" \
    -user "${USER:-l2tpuser}" \
    -pass "${PASS:-l2tppass}" \
    -pool 10.20.0.0/24 \
    -tun tun0 \
    -shape "$SHAPE" \
    -setup-nat
