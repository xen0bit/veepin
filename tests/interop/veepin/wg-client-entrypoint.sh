#!/bin/sh
# veepin WireGuard client for the interop harness. It dials the reference
# responder with flag-configured keys (no wg-quick file — the flag path is what
# the CLI exercises) and runs the data path.
#
# -full-tunnel=false brings the TUN up with just the assigned address and the
# connected /24 route, so a ping to the server's tunnel IP crosses the tunnel
# without hijacking the container's default route. `veepin connect` blocks once
# up; if the server is not ready it fails fast, so we retry until it answers.
set -u

echo "veepin-wg-client: connecting to ${SERVER}:51820 (endpoint), tun ${CLIENT_TUN_IP}"

i=1
while [ "$i" -le 30 ]; do
    veepin connect wireguard \
        -private-key "$CLIENT_PRIVATE" \
        -public-key "$SERVER_PUBLIC" \
        -preshared-key "$PSK" \
        -endpoint "${SERVER}:51820" \
        -address "${CLIENT_TUN_IP}/24" \
        -allowed-ips "${SERVER_TUN_IP}/32" \
        -persistent-keepalive 15 \
        -tun tun0 \
        -full-tunnel=false
    echo "veepin-wg-client: attempt $i failed; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

echo "veepin-wg-client: giving up after $((i - 1)) attempts"
exit 1
