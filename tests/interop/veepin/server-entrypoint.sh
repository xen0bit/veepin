#!/bin/sh
# veepin VPN server container entrypoint for the interop harness.
# -setup-nat brings up the TUN gateway address (pool .1) so a connected peer can
# ping it through the tunnel — that is the data-path assertion.
#
# LISTEN selects the outer transport family: 0.0.0.0 (default, IPv4) or :: (IPv6/
# dual-stack). PUBLIC overrides the advertised address (NAT detection); it
# defaults to the container's first address, which is IPv4.
set -eu

LISTEN="${LISTEN:-0.0.0.0}"
PUB="${PUBLIC:-$(hostname -i | awk '{print $1}')}"
echo "veepin-server: listen $LISTEN, public $PUB, id=$SERVER_ID pool=${POOL:-10.10.10.0/24}"

exec veepin serve ikev2 \
    -listen "$LISTEN" \
    -public "$PUB" \
    -psk "$PSK" \
    -id "$SERVER_ID" \
    -pool "${POOL:-10.10.10.0/24}" \
    -tun tun0 \
    -setup-nat
