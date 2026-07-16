#!/bin/sh
# Reference WireGuard initiator: the real wireguard-go, driven by wg-quick, used
# to prove the veepin *server* against a client it shares no code with. It brings
# up wg0 pointed at the veepin server and holds it open; the harness pings the
# server's tunnel address across it.
set -eu

export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go

mkdir -p /etc/wireguard
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE}
Address = ${CLIENT_TUN_IP}/24

[Peer]
PublicKey = ${SERVER_PUBLIC}
PresharedKey = ${PSK}
Endpoint = ${SERVER}:51820
AllowedIPs = ${SERVER_TUN_IP}/32
PersistentKeepalive = 15
EOF

echo "wg-client: bringing up wg0 (userspace wireguard-go) toward ${SERVER}"
wg-quick up wg0
wg show

echo "wg-client: ready, holding the tunnel open"
while true; do sleep 3600; done
