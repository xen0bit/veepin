#!/bin/sh
# Reference wireguard-go client carrying IPv6 inside the tunnel, against the
# veepin server.
#
# The direction matters. `wgTunnel.sourceAllowed` -- the inbound half of
# cryptokey routing -- runs with verifySource set only on the *server*
# (wireguard/server.go), so a v6-only rejection there is what dropped traffic.
# A client-direction cell would pass with the bug present, because the client
# does not verify inbound sources at all.
#
# The underlay stays IPv4 throughout; only the inner family changes.
set -eu

export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go

mkdir -p /etc/wireguard
cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
PrivateKey = ${CLIENT_PRIVATE}
Address = ${CLIENT_TUN_IP}/24, ${CLIENT_TUN_IP6}/64

[Peer]
PublicKey = ${SERVER_PUBLIC}
PresharedKey = ${PSK}
Endpoint = ${SERVER}:51820
AllowedIPs = ${SERVER_TUN_IP}/32, ${SERVER_TUN_IP6}/128
PersistentKeepalive = 15
CONF

echo "wg-client: bringing up wg0 with ${CLIENT_TUN_IP6} toward ${SERVER}"
wg-quick up wg0
wg show

echo "wg-client: ready, holding the tunnel open"
while true; do sleep 3600; done
