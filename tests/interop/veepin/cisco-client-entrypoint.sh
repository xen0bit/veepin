#!/bin/sh
# veepin Cisco IPsec client for the interop harness. Retries until the gateway is
# ready.
#
# -full-tunnel=true, unlike most cells here, because Mode-Config has no netmask
# to send and strongSwan sends none: the assigned address arrives as a host
# address, so there is no connected route and only a default route through the
# TUN reaches an in-tunnel peer. That is what a real client of this protocol does
# too — it takes a default route, or the split-include list, and never an
# invented subnet mask.
set -u

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

i=1
while [ "$i" -le 40 ]; do
    echo "veepin-cisco-client: connecting to ${SERVER} as ${USER}/${GROUP} (attempt $i)"
    veepin connect cisco \
        -server "$SERVER" \
        -group "$GROUP" -group-psk "$GROUP_PSK" \
        -user "$USER" -pass "$PASSWORD" \
        -tun cisco0 \
        -full-tunnel=true
    echo "veepin-cisco-client: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
