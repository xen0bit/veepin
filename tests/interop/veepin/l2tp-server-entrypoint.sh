#!/bin/sh
# veepin L2TP/IPsec server for the interop harness. -setup-nat assigns the
# gateway address (pool .1 = 10.20.0.1) to the TUN so the kernel answers pings to
# it — the data-path assertion. No -wan, so no MASQUERADE is installed.
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "veepin-l2tp-server: serving l2tp on udp/500, gateway 10.20.0.1"
exec veepin serve l2tp \
    -psk "${PSK:-l2tpsecret}" \
    -user "${USER:-l2tpuser}" \
    -pass "${PASS:-l2tppass}" \
    -pool 10.20.0.0/24 \
    -tun tun0 \
    -setup-nat
