#!/bin/sh
# openconnect Fortinet client for the interop harness.
#
# Waits for the veepin gateway's certificate to appear in the shared volume,
# pins it by fingerprint (openconnect has no "skip verification" flag), then
# connects with --protocol=fortinet. --no-dtls keeps the data channel on TLS,
# which is what veepin's gateway speaks. openconnect's vpnc-script configures the
# interface and routes; the harness then pings the gateway across the tunnel.
set -u

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

# Wait for the server to publish its certificate.
i=1
while [ ! -f /certs/ready ] && [ "$i" -le 60 ]; do
    sleep 1
    i=$((i + 1))
done

# openconnect pins the RFC 7469 SPKI hash (pin-sha256), not the DER cert hash:
# base64(sha256(subjectPublicKeyInfo)).
PIN=$(openssl x509 -in /certs/cert.pem -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl base64)

echo "opnc-fortinet-client: connecting to ${SERVER}, pinned pin-sha256:${PIN}"
echo "$PASSWORD" | openconnect \
    --protocol=fortinet \
    --user="$USER" \
    --passwd-on-stdin \
    --servercert "pin-sha256:${PIN}" \
    --no-dtls \
    --interface=fortinet0 \
    "https://${SERVER}:${PORT:-443}"
