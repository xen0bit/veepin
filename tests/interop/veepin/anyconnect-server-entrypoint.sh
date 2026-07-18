#!/bin/sh
# veepin AnyConnect server for the interop harness. -setup-nat assigns the
# gateway address (pool .1 = 10.11.0.1) to the TUN so the kernel answers pings to
# it — the data-path assertion. No -wan, so no MASQUERADE is installed.
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "veepin-anyconnect-server: serving anyconnect on tcp/443, gateway 10.11.0.1"
exec veepin serve anyconnect \
    -cert /pki/server.crt \
    -key /pki/server.key \
    -user "${USER:-ocuser}" \
    -pass "${PASS:-ocpass}" \
    -pool 10.11.0.0/24 \
    -dns 1.1.1.1 \
    -tun tun0 \
    -setup-nat
