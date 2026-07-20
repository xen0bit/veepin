#!/bin/sh
# The independent aioquic CONNECT-UDP forwarder for the interop harness.
#
# Binds a local UDP socket and forwards to TARGET through the veepin MASQUE proxy
# at SERVER. The harness sends a datagram to the local socket and checks the echo
# target's reply returns. Retries until the proxy is ready.
set -u

i=1
while [ "$i" -le 40 ]; do
    echo "aioquic-masque-udp: forwarding 0.0.0.0:${LISTEN_PORT:-5353} -> ${TARGET} via ${SERVER} (attempt $i)"
    masquepeer udp \
        --server "$SERVER" \
        --port "${PORT:-443}" \
        --listen "0.0.0.0:${LISTEN_PORT:-5353}" \
        --target "$TARGET"
    echo "aioquic-masque-udp: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
