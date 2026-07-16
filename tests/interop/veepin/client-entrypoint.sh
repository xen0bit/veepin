#!/bin/sh
# veepin VPN client (ikev2) container entrypoint for the interop harness.
# -full-tunnel=false brings up the TUN with the assigned address + connected
# /24 route (so we can ping the peer's tunnel IP) without hijacking the default
# route. ikev2 blocks running the data path once connected; if the server is not
# ready yet the connect fails fast, so we retry until it comes up.
set -u

echo "veepin-client: connecting to $SERVER:${PORT:-500} as $CLIENT_ID (server-id=$SERVER_ID)"

i=1
while [ "$i" -le 30 ]; do
    ikev2 \
        -server "$SERVER" \
        -port "${PORT:-500}" \
        -psk "$PSK" \
        -id "$CLIENT_ID" \
        -server-id "$SERVER_ID" \
        -tun tun0 \
        -full-tunnel=false
    echo "veepin-client: attempt $i failed; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

echo "veepin-client: giving up after $((i - 1)) attempts"
exit 1
