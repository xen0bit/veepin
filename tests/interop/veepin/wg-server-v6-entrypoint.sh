#!/bin/sh
# veepin WireGuard server carrying IPv6 inside the tunnel.
#
# The peer's AllowedIPs names a v6 prefix, so an inbound v6 packet has to be
# admitted by wgTunnel.sourceAllowed -- which is the function that read the IPv4
# header only and returned false for everything else. This is the role where
# that runs (verifySource is true on the server and false on the client), so
# this is the direction the cell has to be in.
#
# The v6 address is added to the TUN by hand: the server's own address comes
# from the config's Address line, and only its v4 half is installed by
# -setup-nat today. Adding it here keeps the cell about cryptokey routing
# rather than about address installation.
set -u

mkdir -p /etc/wireguard
cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
PrivateKey = ${SERVER_PRIVATE}
Address = ${SERVER_TUN_IP}/24
ListenPort = 51820

[Peer]
PublicKey = ${CLIENT_PUBLIC}
PresharedKey = ${PSK}
AllowedIPs = ${CLIENT_TUN_IP}/32, ${CLIENT_TUN_IP6}/128
CONF

echo "veepin-wg-server: serving on :51820, inner ${SERVER_TUN_IP6}"
veepin serve wireguard -config /etc/wireguard/wg0.conf -tun tun0 -setup-nat &
VEEPIN_PID=$!

for _ in $(seq 1 60); do
    if ip link show tun0 >/dev/null 2>&1; then break; fi
    sleep 0.5
done
if ! ip link show tun0 >/dev/null 2>&1; then
    echo "veepin-wg-server: tun0 never appeared" >&2
    exit 1
fi

ip -6 addr add "${SERVER_TUN_IP6}/64" dev tun0
ip -6 route replace "${CLIENT_TUN_IP6}/128" dev tun0
echo "veepin-wg-server: tun0 has ${SERVER_TUN_IP6}"

wait $VEEPIN_PID
