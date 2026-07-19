#!/bin/sh
# The independent aioquic CONNECT-IP client for the interop harness.
#
# Dials the veepin proxy, takes the assigned address, brings up its TUN, and
# then pings the veepin proxy's gateway across the tunnel. Retries until the
# proxy is ready.
set -u

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

i=1
while [ "$i" -le 40 ]; do
    echo "aioquic-masque-client: connecting to ${SERVER}:${PORT:-443} (attempt $i)"
    masquepeer client \
        --tun masque0 \
        --server "$SERVER" \
        --port "${PORT:-443}"
    echo "aioquic-masque-client: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
