#!/bin/sh
# veepin SSTP client for the interop harness. It dials the reference SSTP server
# over TLS, authenticates with MS-CHAPv2, sends the crypto binding, and runs the
# PPP/IP data path. -insecure accepts the server's self-signed certificate (SSTP
# still mutually authenticates via MS-CHAPv2); -full-tunnel routes the assigned
# /32 point-to-point link so a ping to the server-side gateway crosses the
# tunnel. `veepin connect` blocks once up; if the server is not ready it fails
# fast, so we retry until it answers.
set -u

echo "sstp-client: connecting to ${SERVER}:${PORT:-443}"

i=1
while [ "$i" -le 40 ]; do
    veepin connect sstp \
        -server "$SERVER" \
        -port "${PORT:-443}" \
        -user "$USER" \
        -pass "$PASS" \
        -insecure \
        -tun tun0 \
        -full-tunnel=true
    echo "sstp-client: attempt $i failed; retrying in 3s"
    i=$((i + 1))
    sleep 3
done

echo "sstp-client: giving up after $((i - 1)) attempts"
exit 1
