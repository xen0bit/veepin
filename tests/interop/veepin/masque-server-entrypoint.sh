#!/bin/sh
# veepin MASQUE (CONNECT-IP) proxy for the interop harness.
#
# HTTP/3 is HTTPS, so the proxy needs a TLS certificate; a throwaway self-signed
# one is generated here since the clients in these cells connect with -insecure
# (or the aioquic peer with verification disabled). -setup-nat brings the TUN up
# with the gateway address and installs forwarding/NAT so the assigned client
# addresses are reachable.
set -eu

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /tmp/proxy.key -out /tmp/proxy.crt -days 1 -nodes \
    -subj "/CN=veepin-masque-proxy" >/dev/null 2>&1

echo "veepin-masque-server: starting on 0.0.0.0:${PORT:-443}, pool ${POOL}"
exec veepin serve masque \
    -listen 0.0.0.0 \
    -port "${PORT:-443}" \
    -pool "$POOL" \
    -cert /tmp/proxy.crt -key /tmp/proxy.key \
    -tun masque0 \
    -setup-nat -wan eth0
