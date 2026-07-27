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

# NO_DTLS=1 keeps the data channel on TLS; otherwise openconnect attaches its own
# DTLS session over the veepin server's UDP channel and prefers it.
#
# This used to be unconditional, with a comment noting that openconnect falls
# back to TLS on its own so the test proved the tunnel either way. That is
# exactly the problem: the cell passed whether or not DTLS ever came up, so the
# DTLS half of the AnyConnect claim was never asserted. The two paths are now
# separate cells -- the plain one pins TLS, the -dtls one requires openconnect to
# report an established DTLS connection.
DTLS_FLAG=""
[ "${NO_DTLS:-0}" = "1" ] && DTLS_FLAG="--no-dtls"

i=1
while [ "$i" -le 40 ]; do
    echo "openconnect: connecting to ${SERVER}:${PORT:-443} (attempt $i) ${DTLS_FLAG}"
    # shellcheck disable=SC2086 # DTLS_FLAG is deliberately word-split
    echo "$PASS" | openconnect \
        --protocol=anyconnect \
        $DTLS_FLAG \
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
