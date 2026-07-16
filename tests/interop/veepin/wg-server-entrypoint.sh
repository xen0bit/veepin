#!/bin/sh
# veepin WireGuard server for the interop harness. It generates a wg-quick server
# config from the shared keys and runs `veepin serve wireguard`, which opens the
# TUN and (via -setup-nat) assigns the gateway address so the kernel answers
# pings to it. No -wan is given, so no MASQUERADE is installed — the harness only
# pings the server's own tunnel address, which needs no forwarding.
set -u

mkdir -p /etc/wireguard
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = ${SERVER_PRIVATE}
Address = ${SERVER_TUN_IP}/24
ListenPort = 51820

[Peer]
PublicKey = ${CLIENT_PUBLIC}
PresharedKey = ${PSK}
AllowedIPs = ${CLIENT_TUN_IP}/32
EOF

echo "veepin-wg-server: serving on :51820, gateway ${SERVER_TUN_IP}"
exec veepin serve wireguard -config /etc/wireguard/wg0.conf -tun tun0 -setup-nat
