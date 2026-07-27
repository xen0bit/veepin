#!/bin/sh
# veepin OpenVPN server with --tls-crypt for the interop harness. Every control
# packet is authenticated and encrypted under the shared static key, and an
# opener failing that check is dropped before any session state exists.
# -setup-nat assigns the gateway address (10.8.0.1) so the kernel answers the
# client's ping — the data-path assertion.
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "veepin-ovpn-server: serving openvpn on udp/1194, with tls-crypt, gateway 10.8.0.1"
exec veepin serve openvpn \
    -ca /pki/ca.crt \
    -cert /pki/server.crt \
    -key /pki/server.key \
    -tls-crypt /pki/ta.key \
    -pool 10.8.0.0/24 \
    -tun tun0 \
    -setup-nat
