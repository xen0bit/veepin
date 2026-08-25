#!/bin/sh
# veepin VPN client container entrypoint for the interop harness.
# -full-tunnel=false brings up the TUN with the assigned address + connected
# /24 route (so we can ping the peer's tunnel IP) without hijacking the default
# route. `veepin connect` blocks running the data path once connected; if the
# server is not
# ready yet the connect fails fast, so we retry until it comes up.
set -u

# TCP carries IKE and ESP over one connection (RFC 8229/9329) instead of UDP; the
# port then names the TCP port rather than the port-500 phase, which is why the
# TCP cells set PORT=4500.
echo "veepin-client: connecting to $SERVER:${PORT:-500} as $CLIENT_ID (proto=${PROTOCOL:-ikev2}, server-id=$SERVER_ID, tcp=${TCP:-false})"

i=1
while [ "$i" -le 30 ]; do
    veepin connect "${PROTOCOL:-ikev2}" \
        -server "$SERVER" \
        -port "${PORT:-500}" \
        -psk "$PSK" \
        -id "$CLIENT_ID" \
        -server-id "$SERVER_ID" \
        -tun tun0 \
        -rekey "${REKEY:-0}" \
        -ike-rekey "${IKE_REKEY:-0}" \
        -post-quantum="${POST_QUANTUM:-false}" \
        -iptfs="${IPTFS:-false}" \
        -iptfs-rate "${IPTFS_RATE:-0}" \
        -tcp="${TCP:-false}" \
        -full-tunnel=false
    echo "veepin-client: attempt $i failed; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

echo "veepin-client: giving up after $((i - 1)) attempts"
exit 1
