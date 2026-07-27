#!/bin/sh
# veepin OpenVPN server with --tls-auth for the interop harness. Every control
# packet carries an HMAC-SHA256 under the shared static key, and one that fails
# the check is dropped before any session state exists.
#
# -key-direction is the *client's* direction (1), so the server verifies with the
# opposite half of the split key. Getting that backwards rejects every packet,
# which is precisely what this cell exists to catch.
#
# -setup-nat assigns the gateway address (10.8.0.1) so the kernel answers the
# client's ping — the data-path assertion.
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "veepin-ovpn-server: serving openvpn on udp/1194, with tls-auth (SHA256), gateway 10.8.0.1"
exec veepin serve openvpn \
    -ca /pki/ca.crt \
    -cert /pki/server.crt \
    -key /pki/server.key \
    -tls-auth /pki/ta.key \
    -auth SHA256 \
    -key-direction 1 \
    -pool 10.8.0.0/24 \
    -tun tun0 \
    -setup-nat
