#!/bin/sh
# veepin MASQUE CONNECT-UDP forwarder for the interop harness.
#
# Binds a local UDP socket and forwards to TARGET through the MASQUE proxy at
# SERVER, using CONNECT-UDP. The harness then sends a datagram to the local
# socket and checks that the echo target's reply comes back. Retries until the
# proxy is ready.
set -u

i=1
while [ "$i" -le 40 ]; do
    echo "veepin-masque-udp: forwarding 127.0.0.1:${LISTEN_PORT:-5353} -> ${TARGET} via ${SERVER} (attempt $i)"
    veepin udp-proxy \
        -server "$SERVER" \
        -port "${PORT:-443}" \
        -insecure \
        -listen "127.0.0.1:${LISTEN_PORT:-5353}" \
        -target "$TARGET"
    echo "veepin-masque-udp: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
