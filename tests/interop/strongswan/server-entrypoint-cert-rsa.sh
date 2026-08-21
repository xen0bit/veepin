#!/bin/sh
# strongSwan responder with RSA-2048 certificate authentication, and IP
# fragments dropped (Direction A: veepin ikev2 client -> strongSwan server).
#
# This cell exists because server-entrypoint-cert.sh cannot fail the thing it
# looks like it tests. That one mints ECDSA P-256 -- the smallest certificate
# there is -- so its IKE_AUTH fits in one datagram and a client that never
# fragments passes it. An RSA-2048 leaf plus an intermediate plus a 256-octet
# signature puts IKE_AUTH at 2.5-3.5 KB, which is where RFC 7383 starts to
# matter.
#
# Two deliberate differences from the ECDSA cell:
#
#   - A three-level chain (root -> intermediate -> leaf), because a leaf alone
#     understates what a real deployment sends and veepin emits the whole chain.
#   - A netfilter rule that drops any IKE datagram over 1400 octets. Without it
#     the kernel reassembles IP fragments happily and the cell proves veepin CAN
#     fragment rather than that it MUST. With it, an unfragmented ~2 KB IKE_AUTH
#     is silently lost and the handshake fails -- which is what the
#     fragmentation-hostile middlebox RFC 7383 was written for does.
set -e

PKI=/pki
mkdir -p "$PKI"

# --- Generate the PKI once (RSA 2048, method 14 sha256WithRSAEncryption). ---
if [ ! -f "$PKI/ready" ]; then
    # Root CA.
    pki --gen --type rsa --size 2048 --outform pem > "$PKI/ca-key.pem"
    pki --self --in "$PKI/ca-key.pem" --type rsa \
        --dn "CN=veepin test root CA" --ca --outform pem > "$PKI/ca-cert.pem"

    # Intermediate CA, so both ends send a chain rather than a lone leaf.
    pki --gen --type rsa --size 2048 --outform pem > "$PKI/int-key.pem"
    pki --pub --in "$PKI/int-key.pem" --type rsa \
        | pki --issue --cacert "$PKI/ca-cert.pem" --cakey "$PKI/ca-key.pem" \
            --dn "CN=veepin test intermediate CA" --ca --outform pem > "$PKI/int-cert.pem"

    pki --gen --type rsa --size 2048 --outform pem > "$PKI/server-key.pem"
    pki --pub --in "$PKI/server-key.pem" --type rsa \
        | pki --issue --cacert "$PKI/int-cert.pem" --cakey "$PKI/int-key.pem" \
            --dn "CN=vpn.example.com" --san vpn.example.com \
            --flag serverAuth --outform pem > "$PKI/server-cert.pem"

    pki --gen --type rsa --size 2048 --outform pem > "$PKI/client-key.pem"
    pki --pub --in "$PKI/client-key.pem" --type rsa \
        | pki --issue --cacert "$PKI/int-cert.pem" --cakey "$PKI/int-key.pem" \
            --dn "CN=client.example.com" --san client.example.com \
            --flag clientAuth --outform pem > "$PKI/client-cert.pem"

    # The client sends leaf + intermediate; concatenate for convenience.
    cat "$PKI/client-cert.pem" "$PKI/int-cert.pem" > "$PKI/client-chain.pem"
fi

# Install the CA chain + server credentials where swanctl looks for them.
mkdir -p /etc/swanctl/x509ca /etc/swanctl/x509 /etc/swanctl/private
cp "$PKI/ca-cert.pem" /etc/swanctl/x509ca/
cp "$PKI/int-cert.pem" /etc/swanctl/x509ca/
cp "$PKI/server-cert.pem" /etc/swanctl/x509/
cp "$PKI/server-key.pem" /etc/swanctl/private/

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

# In-tunnel, pingable address on the strongSwan side (inside local_ts).
ip addr add 10.20.30.254/32 dev lo 2>/dev/null || true

/usr/lib/ipsec/charon &
CHARON=$!

i=0
while [ ! -S /run/charon.vici ] && [ ! -S /var/run/charon.vici ]; do
    i=$((i + 1))
    [ "$i" -gt 80 ] && { echo "strongswan: vici socket never appeared"; exit 1; }
    sleep 0.25
done

swanctl --load-all
touch "$PKI/ready"
echo "strongswan-server: RSA pubkey config loaded, IP fragments dropped; ready as responder (id=vpn.example.com)"

wait "$CHARON"
