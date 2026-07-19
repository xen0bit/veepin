#!/bin/sh
# The independent aioquic CONNECT-IP proxy for the interop harness.
#
# Generates a throwaway self-signed certificate (the veepin client connects with
# -insecure), then runs the aioquic proxy, which brings up its own TUN gateway
# and forwards. The veepin client pings that gateway across the tunnel.
set -eu

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /tmp/proxy.key -out /tmp/proxy.crt -days 1 -nodes \
    -subj "/CN=aioquic-masque-proxy" >/dev/null 2>&1

echo "aioquic-masque-server: starting on 0.0.0.0:${PORT:-443}, gateway ${POOL_BASE}.1"
exec masquepeer server \
    --tun masque0 \
    --port "${PORT:-443}" \
    --pool-base "$POOL_BASE" \
    --cert /tmp/proxy.crt --key /tmp/proxy.key
