#!/bin/sh
# veepin GlobalProtect client for the interop harness. Retries until the gateway
# is ready. -insecure skips verification of the gateway's throwaway certificate;
# -full-tunnel=false brings the TUN up with just the assigned address and its
# connected route, so a ping to the gateway crosses the tunnel without hijacking
# the container's default route.
#
# NO_ESP=1 keeps the client on the SSL tunnel even where the gateway hands out
# keys for the ESP one.
set -u

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

ESP_FLAG=""
[ "${NO_ESP:-0}" = "1" ] && ESP_FLAG="-no-esp"

i=1
while [ "$i" -le 40 ]; do
    echo "veepin-gp-client: connecting to ${SERVER}:${PORT:-443} (attempt $i)"
    # shellcheck disable=SC2086 # ESP_FLAG is deliberately word-split
    veepin connect "${PROTOCOL:-gp}" \
        -server "$SERVER" \
        -port "${PORT:-443}" \
        -user "$USER" -pass "$PASSWORD" \
        -insecure \
        $ESP_FLAG \
        -tun gp0 \
        -full-tunnel=false
    echo "veepin-gp-client: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
