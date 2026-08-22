#!/bin/sh
# veepin OpenVPN server carrying IPv6 inside the tunnel.
#
# -pool6 turns on the dual-stack push: every client gets `ifconfig-ipv6` beside
# `ifconfig`, with its v6 address derived from its v4 one (10.8.0.2 becomes
# fd00:8::2). -setup-nat then puts the server's own fd00:8::1 on the TUN through
# client.DualStackServer, so there is nothing here that touches `ip -6` -- a
# regression in either half stops the ping.
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "veepin-ovpn-server: serving openvpn on udp/1194, gateway 10.8.0.1 + fd00:8::1"
exec veepin serve openvpn \
    -ca /pki/ca.crt \
    -cert /pki/server.crt \
    -key /pki/server.key \
    -pool 10.8.0.0/24 \
    -pool6 fd00:8::/64 \
    -tun tun0 \
    -setup-nat
