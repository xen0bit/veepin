#!/bin/sh
# Reference WireGuard responder carrying IPv6 inside the tunnel, for the veepin
# *client* direction.
#
# The mirror of veepin/wg-server-v6-entrypoint.sh. Here wireguard-go owns the
# host configuration and veepin has to produce a client.Result whose v6 half is
# filled in -- which it did not, for as long as the client parsed the whole
# Address line and kept only the first entry.
set -eu

export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go

mkdir -p /etc/wireguard

cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
Address = ${SERVER_TUN_IP}/24, ${SERVER_TUN_IP6}/64
ListenPort = 51820
PrivateKey = ${SERVER_PRIVATE}

[Peer]
PublicKey = ${CLIENT_PUBLIC}
PresharedKey = ${PSK}
AllowedIPs = ${CLIENT_TUN_IP}/32, ${CLIENT_TUN_IP6}/128
CONF

echo "wg-server: bringing up wg0 (${SERVER_TUN_IP} + ${SERVER_TUN_IP6}) with userspace wireguard-go"
wg-quick up wg0
wg show

echo "wg-server: ready, holding the tunnel open"
while true; do sleep 3600; done
