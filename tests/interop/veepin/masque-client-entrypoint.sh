#!/bin/sh
# veepin MASQUE (CONNECT-IP) client for the interop harness.
#
# `veepin connect` blocks once the tunnel is up; if the proxy is not ready it
# fails fast, so retry until it answers. -insecure skips verification of the
# proxy's throwaway self-signed certificate. -full-tunnel=false brings the TUN up
# with just the assigned address and its connected route, so a ping to the
# proxy's gateway crosses the tunnel without hijacking the container's default
# route.
set -u

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

i=1
while [ "$i" -le 40 ]; do
    echo "veepin-masque-client: connecting to ${SERVER}:${PORT:-443} (attempt $i)"
    veepin connect masque \
        -server "$SERVER" \
        -port "${PORT:-443}" \
        -insecure \
        -tun masque0 \
        -full-tunnel=false
    echo "veepin-masque-client: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
