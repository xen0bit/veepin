#!/bin/sh
# veepin ikev2 server with RSA-2048 certificate authentication, answering a
# strongSwan initiator (Direction B).
#
# The point of this cell is the RESPONDER's IKE_AUTH. veepin's server emits a
# full certificate chain in ike_auth.go the same way the client does in
# client.go, and neither had an outbound size check -- so a veepin server could
# not answer a strongSwan client with an RSA CA either. The strongSwan side
# drops IP fragments, so the response only arrives if the server RFC 7383
# fragments it.
#
# The strongSwan container mints the PKI (it has `pki`; this image does not), so
# this waits for the shared volume the same way the client cell does.
set -eu

PKI=/pki

echo "veepin-server: waiting for the shared PKI in $PKI"
i=0
while [ ! -f "$PKI/ready" ] || [ ! -f "$PKI/server-key.pem" ]; do
    i=$((i + 1))
    [ "$i" -gt 120 ] && { echo "veepin-server: PKI never appeared"; exit 1; }
    sleep 1
done

PUB="$(hostname -i | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -1)"
echo "veepin-server: public $PUB, id=${SERVER_ID} pool=${POOL:-10.10.10.0/24}, RSA certificate auth"

exec veepin serve ikev2 \
    -listen 0.0.0.0 \
    -public "$PUB" \
    -id "$SERVER_ID" \
    -cert "$PKI/server-chain.pem" \
    -key "$PKI/server-key.pem" \
    -client-ca "$PKI/ca-chain.pem" \
    -pool "${POOL:-10.10.10.0/24}" \
    -tun tun0 \
    -setup-nat
