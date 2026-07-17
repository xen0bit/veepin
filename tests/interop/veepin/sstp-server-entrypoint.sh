#!/bin/sh
# veepin SSTP server for the interop harness. -setup-nat assigns the gateway
# address (pool .1 = 10.9.0.1) to the TUN so the kernel answers pings to it — the
# data-path assertion. No -wan, so no MASQUERADE is installed.
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "veepin-sstp-server: serving sstp on tcp/443, gateway 10.9.0.1"
exec veepin serve sstp \
    -cert /pki/server.crt \
    -key /pki/server.key \
    -user "${USER:-sstpuser}" \
    -pass "${PASS:-sstppass}" \
    -pool 10.9.0.0/24 \
    -tun tun0 \
    -setup-nat
