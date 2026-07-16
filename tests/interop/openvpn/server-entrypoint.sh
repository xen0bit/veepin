#!/bin/sh
# Start the reference OpenVPN server, ensuring the TUN device node exists.
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "openvpn-server: starting on udp/1194, tun 10.8.0.1"
exec openvpn --config /server.conf
