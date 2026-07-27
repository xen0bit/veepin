#!/bin/sh
# openconnect GlobalProtect client for the interop harness.
#
# Waits for the veepin gateway's certificate to appear in the shared volume,
# pins it by fingerprint (openconnect has no "skip verification" flag), then
# connects with --protocol=gp.
#
# --usergroup=gateway is what makes openconnect talk to the /ssl-vpn/ endpoints
# directly instead of treating the host as a portal first. NO_ESP=1 keeps the
# data path on the TLS tunnel; otherwise openconnect activates ESP and prefers
# it, which is the path the veepin gateway's UDP listener serves.
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

# openconnect spells "do not use the UDP data path" --no-dtls for every protocol,
# including the ones whose UDP path is ESP rather than DTLS.
ESP_FLAG=""
[ "${NO_ESP:-0}" = "1" ] && ESP_FLAG="--no-dtls"

echo "opnc-gp-client: connecting to ${SERVER}, pinned pin-sha256:${PIN} ${ESP_FLAG}"
# shellcheck disable=SC2086 # the flag var is deliberately word-split
echo "$PASSWORD" | openconnect \
    --protocol=gp \
    --usergroup=gateway \
    --user="$USER" \
    --passwd-on-stdin \
    --servercert "pin-sha256:${PIN}" \
    $ESP_FLAG \
    --interface=gp0 \
    "https://${SERVER}:${PORT:-443}"
