#!/bin/sh
# veepin OpenVPN server for the interop harness. -setup-nat assigns the gateway
# address (pool .1 = 10.8.0.1) to the TUN so the kernel answers pings to it — the
# data-path assertion. No -wan, so no MASQUERADE is installed (the harness only
# pings the gateway, it does not route to the internet).
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "veepin-ovpn-server: serving openvpn on udp/1194, gateway 10.8.0.1"
exec veepin serve openvpn \
    -ca /pki/ca.crt \
    -cert /pki/server.crt \
    -key /pki/server.key \
    -pool 10.8.0.0/24 \
    -tun tun0 \
    -setup-nat
