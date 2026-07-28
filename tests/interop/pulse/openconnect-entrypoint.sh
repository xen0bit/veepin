#!/bin/sh
# openconnect Ivanti Connect Secure client for the interop harness.
#
# Waits for the veepin gateway's certificate to appear in the shared volume,
# pins it by fingerprint (openconnect has no "skip verification" flag), then
# connects with --protocol=pulse.
#
# NO_ESP=1 keeps the data path on the IF-T/TLS connection; otherwise openconnect
# takes the ESP keys the gateway pushes and prefers UDP.
set -u

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

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

# openconnect spells "do not use the UDP data path" --no-dtls for every protocol,
# including the ones whose UDP path is ESP rather than DTLS.
ESP_FLAG=""
[ "${NO_ESP:-0}" = "1" ] && ESP_FLAG="--no-dtls"

echo "opnc-pulse-client: connecting to ${SERVER}, pinned pin-sha256:${PIN} ${ESP_FLAG}"
# shellcheck disable=SC2086 # the flag var is deliberately word-split
echo "$PASSWORD" | openconnect \
    --protocol=pulse \
    --user="$USER" \
    --passwd-on-stdin \
    --servercert "pin-sha256:${PIN}" \
    $ESP_FLAG \
    --interface=pulse0 \
    "https://${SERVER}:${PORT:-443}"
