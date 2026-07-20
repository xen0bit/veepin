#!/bin/sh
# openconnect Fortinet client for the interop harness.
#
# Waits for the veepin gateway's certificate to appear in the shared volume,
# pins it by fingerprint (openconnect has no "skip verification" flag), then
# connects with --protocol=fortinet. NO_DTLS=1 keeps the data channel on TLS;
# otherwise openconnect brings its DTLS channel up alongside the TLS tunnel and
# prefers it, which is the path the veepin gateway's UDP listener serves.
# openconnect's vpnc-script configures the interface and routes; the harness then
# pings the gateway across the tunnel.
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

DTLS_FLAG=""
[ "${NO_DTLS:-0}" = "1" ] && DTLS_FLAG="--no-dtls"

# A TOTP secret makes openconnect generate the code for the gateway's ret=2
# challenge itself, with no prompt -- which is what makes 2FA testable
# unattended.
#
# The "base32:" prefix is required: openconnect treats a bare --token-secret as
# RAW ASCII bytes, so passing the base32 text unprefixed silently derives a
# different key and every generated code is wrong.
TOKEN_FLAG=""
[ -n "${TOTP_SECRET:-}" ] && TOKEN_FLAG="--token-mode=totp --token-secret=base32:${TOTP_SECRET}"

echo "opnc-fortinet-client: connecting to ${SERVER}, pinned pin-sha256:${PIN} ${DTLS_FLAG}"
# shellcheck disable=SC2086 # the flag vars are deliberately word-split
echo "$PASSWORD" | openconnect \
    --protocol=fortinet \
    --user="$USER" \
    --passwd-on-stdin \
    --servercert "pin-sha256:${PIN}" \
    $DTLS_FLAG $TOKEN_FLAG \
    --interface=fortinet0 \
    "https://${SERVER}:${PORT:-443}"
