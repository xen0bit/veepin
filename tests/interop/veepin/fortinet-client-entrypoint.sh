#!/bin/sh
# veepin Fortinet client for the interop harness. Retries until the gateway is
# ready. -insecure skips verification of the gateway's throwaway certificate;
# -full-tunnel=false brings the TUN up with just the assigned address and its
# connected route, so a ping to the gateway crosses the tunnel without hijacking
# the container's default route.
set -u

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

i=1
while [ "$i" -le 40 ]; do
    echo "veepin-fortinet-client: connecting to ${SERVER}:${PORT:-443} (attempt $i)"
    veepin connect fortinet \
        -server "$SERVER" \
        -port "${PORT:-443}" \
        -user "$USER" -pass "$PASSWORD" \
        -insecure \
        -tun fortinet0 \
        -full-tunnel=false
    echo "veepin-fortinet-client: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
