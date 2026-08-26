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

# A pq- cell bind-mounts an ML-DSA credential at /pki, and this branch uses it
# instead of minting one. The runtime image is bookworm, whose OpenSSL 3.0 has no
# ML-DSA, so the test mints it in Go -- see generateMLDSAServerCert. With /pki
# unmounted the classical cells mint exactly what they always did.
if [ -d /pki ]; then
    CERT=/pki/server.crt
    KEY=/pki/server.key
else
    CERT=/tmp/proxy.crt
    KEY=/tmp/proxy.key
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$KEY" -out "$CERT" -days 1 -nodes \
        -subj "/CN=veepin-masque-proxy" >/dev/null 2>&1
fi

# SHAPE pads the first N bytes of each inner flow out to the inner MTU. The
# filler goes inside the DATAGRAM capsule's value, after the IP packet: RFC
# 9484's context-0 payload has no length of its own, so the receiver hands
# everything after the context ID to its TUN and the kernel delimits the real
# packet by the inner header's Total Length. The shaped cell exists to prove
# aioquic does exactly that without being told anything.
echo "veepin-masque-server: serving ${PROTOCOL:-masque} on 0.0.0.0:${PORT:-443}, pool ${POOL}, shape ${SHAPE:-0}"
exec veepin serve "${PROTOCOL:-masque}" \
    -listen 0.0.0.0 \
    -port "${PORT:-443}" \
    -pool "$POOL" \
    -shape "${SHAPE:-0}" \
    -cert "$CERT" -key "$KEY" \
    -tun masque0 \
    -setup-nat -wan eth0
