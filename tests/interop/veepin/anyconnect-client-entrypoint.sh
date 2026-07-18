#!/bin/sh
# veepin AnyConnect client for the interop harness. It runs the XML credential
# exchange and the CONNECT against the reference server, then carries IP over the
# CSTP framing. -insecure accepts the server's self-signed certificate; the
# password is the real authentication. -full-tunnel routes the assigned address
# so a ping to the server's tunnel address crosses the tunnel. `veepin connect`
# blocks once up; if the server is not ready it fails fast, so we retry.
set -u

echo "anyconnect-client: connecting to ${SERVER}:${PORT:-443}"

i=1
while [ "$i" -le 40 ]; do
    veepin connect anyconnect \
        -server "$SERVER" \
        -port "${PORT:-443}" \
        -user "$USER" \
        -pass "$PASS" \
        -insecure \
        -tun tun0 \
        -full-tunnel=true
    echo "anyconnect-client: attempt $i failed; retrying in 3s"
    i=$((i + 1))
    sleep 3
done

echo "anyconnect-client: giving up after $((i - 1)) attempts"
exit 1
