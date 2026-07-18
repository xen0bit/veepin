#!/bin/sh
# Reference AnyConnect server: ocserv with password authentication. The veepin
# client authenticates, is assigned an address from 10.12.0.0/24, and pings
# 10.12.0.1 — ocserv's own tunnel-side address — across the tunnel.
set -e

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

install -d -m 755 /etc/ocserv
cp /conf/ocserv.conf /etc/ocserv/ocserv.conf

# ocpasswd stores an MD5-crypt hash; create the user non-interactively.
printf '%s\n%s\n' "${PASS:-ocpass}" "${PASS:-ocpass}" \
    | ocpasswd -c /etc/ocserv/ocpasswd "${USER:-ocuser}"

echo "ocserv: serving AnyConnect on tcp/443, tunnel network 10.12.0.0/24"
exec ocserv -f -d 1 -c /etc/ocserv/ocserv.conf
