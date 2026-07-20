#!/bin/sh
# veepin Fortinet SSL VPN gateway for the interop harness.
#
# Generates a throwaway certificate into the shared /certs volume, with a SAN
# matching the container name so the openconnect client can verify it by pinning
# its fingerprint. -setup-nat brings the TUN up with the gateway address and
# installs forwarding/NAT so the assigned client addresses are reachable.
set -eu

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

mkdir -p /certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /certs/key.pem -out /certs/cert.pem -days 1 -nodes \
    -subj "/CN=veepin-fortinet-server" \
    -addext "subjectAltName=DNS:veepin-fortinet-server" >/dev/null 2>&1
chmod 0644 /certs/cert.pem
# Signal readiness to the client, which waits on this file.
touch /certs/ready

TOTP_FLAG=""
if [ -n "${TOTP_SECRET:-}" ]; then
    TOTP_FLAG="-totp ${TOTP_SECRET}"
    echo "veepin-fortinet-server: requiring a second factor from ${USER}"
fi

echo "veepin-fortinet-server: starting on 0.0.0.0:${PORT:-443}, pool ${POOL}"
# shellcheck disable=SC2086 # TOTP_FLAG is deliberately word-split into two args
exec veepin serve fortinet \
    $TOTP_FLAG \
    -listen 0.0.0.0 \
    -port "${PORT:-443}" \
    -pool "$POOL" \
    -cert /certs/cert.pem -key /certs/key.pem \
    -user "$USER" -pass "$PASSWORD" \
    -tun fortinet0 \
    -setup-nat -wan eth0
