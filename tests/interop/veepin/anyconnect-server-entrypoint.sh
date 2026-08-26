#!/bin/sh
# veepin AnyConnect server for the interop harness. -setup-nat assigns the
# gateway address (pool .1 = 10.11.0.1) to the TUN so the kernel answers pings to
# it — the data-path assertion. No -wan, so no MASQUERADE is installed.
#
# SHAPE is the per-flow downstream shaping budget in bytes (0, the default, is
# off). A non-zero value pads the CSTP data payload past the inner IP packet,
# which the peer must trim by the IP header's own length.
set -eu
SHAPE="${SHAPE:-0}"
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "veepin-anyconnect-server: serving ${PROTOCOL:-anyconnect} on tcp/443, gateway 10.11.0.1, shape $SHAPE"
exec veepin serve "${PROTOCOL:-anyconnect}" \
    -cert /pki/server.crt \
    -key /pki/server.key \
    -user "${USER:-ocuser}" \
    -pass "${PASS:-ocpass}" \
    -pool 10.11.0.0/24 \
    -dns 1.1.1.1 \
    -tun tun0 \
    -shape "$SHAPE" \
    -setup-nat
