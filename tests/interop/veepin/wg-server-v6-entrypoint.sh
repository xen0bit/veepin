#!/bin/sh
# veepin WireGuard server carrying IPv6 inside the tunnel.
#
# The peer's AllowedIPs names a v6 prefix, so an inbound v6 packet has to be
# admitted by wgTunnel.sourceAllowed -- which is the function that read the IPv4
# header only and returned false for everything else. This is the role where
# that runs (verifySource is true on the server and false on the client), so
# this is the direction the cell has to be in.
#
# The v6 address used to be added here by hand, with a comment explaining that
# only the v4 half of the config's Address line was installed by -setup-nat.
# That comment was an accurate description of a gap, and closing it is what this
# cell now proves: the config names both families, veepin implements
# client.DualStackServer, and internal/hostnet puts the address on the interface
# along with v6 forwarding. Nothing below touches `ip -6`, and if that changed
# the ping would stop.
set -u

mkdir -p /etc/wireguard
cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
PrivateKey = ${SERVER_PRIVATE}
Address = ${SERVER_TUN_IP}/24, ${SERVER_TUN_IP6}/64
ListenPort = 51820

[Peer]
PublicKey = ${CLIENT_PUBLIC}
PresharedKey = ${PSK}
AllowedIPs = ${CLIENT_TUN_IP}/32, ${CLIENT_TUN_IP6}/128
CONF

echo "veepin-wg-server: serving on :51820, inner ${SERVER_TUN_IP} + ${SERVER_TUN_IP6}"
exec veepin serve wireguard -config /etc/wireguard/wg0.conf -tun tun0 -setup-nat
