#!/bin/sh
# Reference WireGuard responder: brings up a wg0 interface with the userspace
# wireguard-go, configured from the keys the compose file shares with the veepin
# client. It listens on 51820 with the client as its single peer, then holds the
# tunnel open so the harness can ping across it.
set -eu

# wg-quick drives the userspace implementation instead of the kernel module.
export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go

mkdir -p /etc/wireguard

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${SERVER_TUN_IP}/24
ListenPort = 51820
PrivateKey = ${SERVER_PRIVATE}

[Peer]
PublicKey = ${CLIENT_PUBLIC}
PresharedKey = ${PSK}
AllowedIPs = ${CLIENT_TUN_IP}/32
EOF

echo "wg-server: bringing up wg0 (${SERVER_TUN_IP}) with userspace wireguard-go"
wg-quick up wg0
wg show

echo "wg-server: ready, holding the tunnel open"
# Sleep forever; the tunnel lives in wireguard-go, not this shell.
while true; do sleep 3600; done
