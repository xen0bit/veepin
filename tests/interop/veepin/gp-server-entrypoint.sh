#!/bin/sh
# veepin GlobalProtect gateway for the interop harness.
#
# Generates a throwaway certificate into the shared /certs volume, with a SAN
# matching the container name so the openconnect client can verify it by pinning
# its fingerprint. -setup-nat brings the TUN up with the gateway address and
# installs forwarding/NAT so the assigned client addresses are reachable.
#
# -public is given explicitly: the gateway advertises it as the ESP endpoint and
# the client sends its activation pings there, and inside compose the container's
# own address is what the client can reach.
#
# SHAPE is the per-flow downstream shaping budget in bytes (0, the default, is
# off). NO_ESP=1 leaves the UDP port unbound, serving the TLS tunnel only.
set -eu
SHAPE="${SHAPE:-0}"

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

mkdir -p /certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /certs/key.pem -out /certs/cert.pem -days 1 -nodes \
    -subj "/CN=veepin-gp-server" \
    -addext "subjectAltName=DNS:veepin-gp-server" >/dev/null 2>&1
chmod 0644 /certs/cert.pem
# Signal readiness to the client, which waits on this file.
touch /certs/ready

PUBLIC=$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)

ESP_FLAG=""
if [ "${NO_ESP:-0}" = "1" ]; then
    ESP_FLAG="-no-esp"
    echo "veepin-gp-server: serving the SSL tunnel only"
fi

echo "veepin-gp-server: starting on 0.0.0.0:${PORT:-443}, pool ${POOL}, public ${PUBLIC}, shape ${SHAPE}"
# shellcheck disable=SC2086 # ESP_FLAG is deliberately word-split
exec veepin serve gp \
    $ESP_FLAG \
    -listen 0.0.0.0 \
    -port "${PORT:-443}" \
    -public "$PUBLIC" \
    -pool "$POOL" \
    -cert /certs/cert.pem -key /certs/key.pem \
    -user "$USER" -pass "$PASSWORD" \
    -tun gp0 \
    -shape "$SHAPE" \
    -setup-nat -wan eth0
