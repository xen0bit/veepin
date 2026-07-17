#!/bin/sh
# Reference OpenVPN client for the interop harness. `client` mode retries the
# connection on its own until the veepin server answers, so no wrapper loop is
# needed; the harness pings the server's tunnel gateway once the tunnel is up.
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "openvpn-client: connecting to veepin-ovpn-server:1194"
exec openvpn --config /client.conf
