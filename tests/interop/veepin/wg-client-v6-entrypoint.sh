#!/bin/sh
# veepin WireGuard client carrying IPv6 inside the tunnel.
#
# -address names both families, which is what wg-quick's Address line does on a
# dual-stack interface. The client used to parse the whole list, validate it,
# and keep only the first entry -- so this exact invocation came up IPv4-only,
# silently, and a ping to the server's v6 tunnel address had nowhere to leave
# from. The Result now carries AssignedIP6/Prefix6 and dataplane's client
# routing installs it, the same code path ikev2 has always used.
set -u

echo "veepin-wg-client: connecting to ${SERVER}:51820, tun ${CLIENT_TUN_IP} + ${CLIENT_TUN_IP6}"

i=1
while [ "$i" -le 30 ]; do
    veepin connect wireguard \
        -private-key "$CLIENT_PRIVATE" \
        -public-key "$SERVER_PUBLIC" \
        -preshared-key "$PSK" \
        -endpoint "${SERVER}:51820" \
        -address "${CLIENT_TUN_IP}/24,${CLIENT_TUN_IP6}/64" \
        -allowed-ips "${SERVER_TUN_IP}/32,${SERVER_TUN_IP6}/128" \
        -persistent-keepalive 15 \
        -tun tun0 \
        -full-tunnel=false
    echo "veepin-wg-client: attempt $i failed; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

echo "veepin-wg-client: giving up after $((i - 1)) attempts"
exit 1
