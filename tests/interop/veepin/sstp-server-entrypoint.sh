#!/bin/sh
# veepin SSTP server for the interop harness. -setup-nat assigns the gateway
# address (pool .1 = 10.9.0.1) to the TUN so the kernel answers pings to it — the
# data-path assertion. No -wan, so no MASQUERADE is installed.
#
# SHAPE is the per-flow downstream shaping budget in bytes (0, the default, is
# off). A non-zero value pads the PPP information field past the inner IP packet
# (RFC 1661 §5.1), which the peer must trim by the IP header's own length.
set -eu
SHAPE="${SHAPE:-0}"
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "veepin-sstp-server: serving ${PROTOCOL:-sstp} on tcp/443, gateway 10.9.0.1, shape $SHAPE"
exec veepin serve "${PROTOCOL:-sstp}" \
    -cert /pki/server.crt \
    -key /pki/server.key \
    -user "${USER:-sstpuser}" \
    -pass "${PASS:-sstppass}" \
    -pool 10.9.0.0/24 \
    -tun tun0 \
    -shape "$SHAPE" \
    -setup-nat
