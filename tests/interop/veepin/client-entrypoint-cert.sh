#!/bin/sh
# veepin VPN client entrypoint for certificate (pubkey) interop against the
# strongSwan server. It waits for the strongSwan side to publish the shared PKI
# in /pki, then connects with its client certificate/key and the CA that verifies
# the server. -full-tunnel=false brings up the assigned address + connected route
# without hijacking the default route.
set -u

PKI=/pki

echo "veepin-client: waiting for the shared PKI in $PKI"
i=0
while [ ! -f "$PKI/ready" ] || [ ! -f "$PKI/client-key.pem" ]; do
    i=$((i + 1))
    [ "$i" -gt 120 ] && { echo "veepin-client: PKI never appeared"; exit 1; }
    sleep 1
done

# CLIENT_CERT lets a cell hand over a chain file (leaf + intermediate) instead
# of the lone leaf. The RSA cell does; the ECDSA one leaves it unset.
CERT="${CLIENT_CERT:-$PKI/client-cert.pem}"

echo "veepin-client: connecting to $SERVER as $CLIENT_ID with $CERT (server-id=$SERVER_ID)"

i=1
while [ "$i" -le 30 ]; do
    veepin connect ikev2 \
        -server "$SERVER" \
        -port "${PORT:-500}" \
        -id "$CLIENT_ID" \
        -server-id "$SERVER_ID" \
        -cert "$CERT" \
        -key "$PKI/client-key.pem" \
        -ca "$PKI/ca-cert.pem" \
        -tun tun0 \
        -full-tunnel=false
    echo "veepin-client: attempt $i failed; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

echo "veepin-client: giving up after $((i - 1)) attempts"
exit 1
