#!/bin/sh
# veepin OpenVPN server for the interop harness. -setup-nat assigns the gateway
# address (pool .1 = 10.8.0.1) to the TUN so the kernel answers pings to it — the
# data-path assertion. No -wan, so no MASQUERADE is installed (the harness only
# pings the gateway, it does not route to the internet).
#
# SHAPE is the per-flow downstream shaping budget in bytes (0, the default, is
# off). A non-zero value pads the data-channel payload past the inner IP packet,
# which the peer must trim by the IP header's own length.
set -eu
SHAPE="${SHAPE:-0}"
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "veepin-ovpn-server: serving ${PROTOCOL:-openvpn} on udp/1194, gateway 10.8.0.1, shape $SHAPE"
exec veepin serve "${PROTOCOL:-openvpn}" \
    -ca /pki/ca.crt \
    -cert /pki/server.crt \
    -key /pki/server.key \
    -pool 10.8.0.0/24 \
    -tun tun0 \
    -shape "$SHAPE" \
    -setup-nat
