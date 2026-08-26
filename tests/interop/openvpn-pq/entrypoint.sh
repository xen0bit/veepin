#!/bin/sh
# The reference post-quantum OpenVPN peer, in either role. ROLE picks it; one
# image serves both directions, as ../openvpn's does for its four profiles.
#
# The assertion up front is deliberate. If this image ever regresses to an
# OpenSSL without ML-DSA, every attempt would fail inside the TLS handshake for a
# reason that reads like a veepin bug; failing here names the real cause while
# somebody is still looking at the log.
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200

openssl list -signature-algorithms | grep -qi ml-dsa || {
    echo "openvpn-pq: FATAL: this OpenSSL has no ML-DSA" >&2
    exit 1
}
openssl list -kem-algorithms | grep -qi X25519MLKEM768 || {
    echo "openvpn-pq: FATAL: this OpenSSL has no X25519MLKEM768 group" >&2
    exit 1
}

case "${ROLE:-server}" in
    server)
        echo "openvpn-pq: server on udp/1194, ML-DSA-65 PKI, ML-KEM-only groups"
        exec openvpn --config /server-pq.conf
        ;;
    client)
        echo "openvpn-pq: client -> ${SERVER:-veepin-pq-ovpn-server}:1194, ML-DSA-65 PKI, ML-KEM-only groups"
        exec openvpn --config /client-pq.conf
        ;;
    *)
        echo "openvpn-pq: unknown ROLE '${ROLE}'" >&2
        exit 1
        ;;
esac
