#!/bin/sh
# strongSwan initiator with RSA-2048 certificate authentication, and IP
# fragments dropped (Direction B: here -> veepin serve ikev2).
#
# This container mints the PKI because it is the one with strongSwan's `pki`
# tool; the veepin server image has no PEM generator. It publishes into the
# shared /pki volume:
#
#   ca-chain.pem      root + intermediate, what the veepin server verifies with
#   server-chain.pem  the veepin server's leaf + intermediate, what it sends
#   server-key.pem    the veepin server's private key
#
# The oversize-datagram drop below is the assertion. The veepin server's
# IKE_AUTH response carries a two-certificate chain and a 256-octet RSA
# signature, so it is near 2 KB; if the server sends it whole this side refuses
# it and the handshake never completes. It completes
# only if the veepin RESPONDER performs RFC 7383 fragmentation -- which is a
# separate code path from the initiator's, in ike_auth.go rather than client.go,
# and had the same missing size check.
set -e

PKI=/pki
mkdir -p "$PKI"

if [ ! -f "$PKI/ready" ]; then
    pki --gen --type rsa --size 2048 --outform pem > "$PKI/ca-key.pem"
    pki --self --in "$PKI/ca-key.pem" --type rsa \
        --dn "CN=veepin test root CA" --ca --outform pem > "$PKI/ca-cert.pem"

    pki --gen --type rsa --size 2048 --outform pem > "$PKI/int-key.pem"
    pki --pub --in "$PKI/int-key.pem" --type rsa \
        | pki --issue --cacert "$PKI/ca-cert.pem" --cakey "$PKI/ca-key.pem" \
            --dn "CN=veepin test intermediate CA" --ca --outform pem > "$PKI/int-cert.pem"

    # The veepin server's credentials.
    pki --gen --type rsa --size 2048 --outform pem > "$PKI/server-key.pem"
    pki --pub --in "$PKI/server-key.pem" --type rsa \
        | pki --issue --cacert "$PKI/int-cert.pem" --cakey "$PKI/int-key.pem" \
            --dn "CN=vpn.example.com" --san vpn.example.com \
            --flag serverAuth --outform pem > "$PKI/server-cert.pem"

    # This container's own credentials.
    pki --gen --type rsa --size 2048 --outform pem > "$PKI/client-key.pem"
    pki --pub --in "$PKI/client-key.pem" --type rsa \
        | pki --issue --cacert "$PKI/int-cert.pem" --cakey "$PKI/int-key.pem" \
            --dn "CN=client.example.com" --san client.example.com \
            --flag clientAuth --outform pem > "$PKI/client-cert.pem"

    cat "$PKI/server-cert.pem" "$PKI/int-cert.pem" > "$PKI/server-chain.pem"
    cat "$PKI/ca-cert.pem" "$PKI/int-cert.pem" > "$PKI/ca-chain.pem"
fi

mkdir -p /etc/swanctl/x509ca /etc/swanctl/x509 /etc/swanctl/private
cp "$PKI/ca-cert.pem" /etc/swanctl/x509ca/
cp "$PKI/int-cert.pem" /etc/swanctl/x509ca/
cp "$PKI/client-cert.pem" /etc/swanctl/x509/
cp "$PKI/client-key.pem" /etc/swanctl/private/

# Refuse any IKE datagram over 1400 octets, however it arrived. This is the
# assertion, not a hardening measure: an IKE_AUTH carrying an RSA chain is
# ~2 KB, so the handshake completes only if the sender split it into RFC 7383
# fragments, each of which is under the 1280-octet threshold and passes.
#
# It is a length match rather than the obvious `iptables -A INPUT -f -j DROP`,
# and that is worth writing down. Netfilter's connection-tracking defragmenter
# runs at NF_IP_PRI_CONNTRACK_DEFRAG (-400), ahead of both the raw table (-300)
# and the filter table, so by the time any rule sees the packet it has already
# been reassembled and `-f` matches nothing. That rule was tried here first, and
# the cell passed with outbound fragmentation deliberately disabled -- a
# fixture that could not fail, which is precisely what this cell exists to stop.
iptables -A INPUT -p udp --dport 500 -m length --length 1400:65535 -j DROP
iptables -A INPUT -p udp --dport 4500 -m length --length 1400:65535 -j DROP

# Signal the veepin server that its credentials are on the volume.
touch "$PKI/ready"

/usr/lib/ipsec/charon &
CHARON=$!

i=0
while [ ! -S /run/charon.vici ] && [ ! -S /var/run/charon.vici ]; do
    i=$((i + 1))
    [ "$i" -gt 80 ] && { echo "strongswan: vici socket never appeared"; exit 1; }
    sleep 0.25
done

swanctl --load-all
echo "strongswan-client: RSA pubkey config loaded, IP fragments dropped; initiating to veepin-server"

i=1
while [ "$i" -le 30 ]; do
    if swanctl --initiate --child ss; then
        echo "strongswan-client: CHILD_SA established"
        break
    fi
    echo "strongswan-client: initiate attempt $i failed; retrying in 2s"
    i=$((i + 1))
    sleep 2
done

wait "$CHARON"
