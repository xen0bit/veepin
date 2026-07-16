#!/bin/sh
# veepin VPN server container entrypoint for the interop harness.
# -setup-nat brings up the TUN gateway address (pool .1) so a connected peer can
# ping it through the tunnel — that is the data-path assertion.
set -eu

PUB=$(hostname -i | awk '{print $1}')
echo "veepin-server: container IP $PUB, id=$SERVER_ID pool=${POOL:-10.10.10.0/24}"

exec veepin serve ikev2 \
    -listen 0.0.0.0 \
    -public "$PUB" \
    -psk "$PSK" \
    -id "$SERVER_ID" \
    -pool "${POOL:-10.10.10.0/24}" \
    -tun tun0 \
    -setup-nat
