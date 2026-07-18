#!/bin/sh
# Reference AnyConnect client: openconnect against the veepin server. It runs the
# XML credential exchange, issues CONNECT, applies the addressing veepin returns
# in the response headers via vpnc-script, and then carries IP over CSTP.
set -u

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

# openconnect refuses an unverifiable certificate unless told which one to trust.
# Pinning the throwaway cert is the non-interactive equivalent of the veepin
# client's -insecure, and keeps the password the real authentication. The pin is
# base64(sha256(SubjectPublicKeyInfo)) — the HPKP form openconnect expects, not a
# digest of the whole certificate.
PIN=$(openssl x509 -in /pki/server.crt -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary \
    | openssl base64)
echo "openconnect: pinning server certificate pin-sha256:$PIN"

# DTLS is left enabled so this exercises the veepin server's UDP data channel.
# openconnect falls back to TLS on its own if that does not come up, so the test
# still proves the tunnel either way — the logs say which was used.
i=1
while [ "$i" -le 40 ]; do
    echo "openconnect: connecting to ${SERVER}:${PORT:-443} (attempt $i)"
    echo "$PASS" | openconnect \
        --protocol=anyconnect \
        --user="$USER" \
        --passwd-on-stdin \
        --servercert "pin-sha256:$PIN" \
        --script /usr/share/vpnc-scripts/vpnc-script \
        --interface tun0 \
        --non-inter \
        "${SERVER}:${PORT:-443}"
    echo "openconnect: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
