#!/bin/sh
# veepin VPN server container entrypoint for the interop harness.
# -setup-nat brings up the TUN gateway address (pool .1) so a connected peer can
# ping it through the tunnel — that is the data-path assertion.
#
# LISTEN selects the outer transport family: 0.0.0.0 (default, IPv4) or :: (IPv6/
# dual-stack). PUBLIC overrides the advertised address (NAT detection); it
# defaults to the container's first address, which is IPv4.
#
# SHAPE is the per-flow downstream shaping budget in bytes (0, the default, is
# off). A non-zero value makes the server pad outbound ESP with RFC 4303 §2.7
# TFC padding, which the peer must tolerate — that is what the shaped cell
# proves.
set -eu

LISTEN="${LISTEN:-0.0.0.0}"
SHAPE="${SHAPE:-0}"
PUB="${PUBLIC:-$(hostname -i | awk '{print $1}')}"
echo "veepin-server: listen $LISTEN, public $PUB, id=$SERVER_ID pool=${POOL:-10.10.10.0/24} shape=$SHAPE"

exec veepin serve ikev2 \
    -listen "$LISTEN" \
    -public "$PUB" \
    -psk "$PSK" \
    -id "$SERVER_ID" \
    -pool "${POOL:-10.10.10.0/24}" \
    -tun tun0 \
    -shape "$SHAPE" \
    -setup-nat
