#!/bin/sh
# veepin OpenVPN client for the interop harness. It dials the reference OpenVPN
# server with the shared PKI and runs the data path. -full-tunnel=false brings
# the TUN up with the pushed address and the connected /24 route, so a ping to
# the server's tunnel IP crosses the tunnel without hijacking the default route.
# `veepin connect` blocks once up; if the server is not ready it fails fast, so
# we retry until it answers.
set -u

echo "veepin-ovpn-client: connecting to ${SERVER}:1194"

i=1
while [ "$i" -le 30 ]; do
    veepin connect openvpn \
        -remote "$SERVER" -port 1194 \
        -ca /pki/ca.crt \
        -cert /pki/client.crt \
        -key /pki/client.key \
        -tun tun0 \
        -full-tunnel=false
    echo "veepin-ovpn-client: attempt $i failed; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

echo "veepin-ovpn-client: giving up after $((i - 1)) attempts"
exit 1
