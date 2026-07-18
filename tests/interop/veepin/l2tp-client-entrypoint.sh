#!/bin/sh
# veepin L2TP/IPsec client for the interop harness. It runs IKEv1 Main Mode with
# the PSK, Quick Mode for the ESP transport SA, then L2TP and PPP inside it, and
# applies the address IPCP assigns. -full-tunnel routes the assigned /32
# point-to-point link so a ping to the server-side gateway crosses the tunnel.
# `veepin connect` blocks once up; if the server is not ready it fails fast, so
# we retry until it answers.
set -u

echo "l2tp-client: connecting to ${SERVER}:${PORT:-500}"

i=1
while [ "$i" -le 40 ]; do
    veepin connect l2tp \
        -server "$SERVER" \
        -port "${PORT:-500}" \
        -psk "$PSK" \
        -user "$USER" \
        -pass "$PASS" \
        -tun tun0 \
        -full-tunnel=true
    echo "l2tp-client: attempt $i failed; retrying in 3s"
    i=$((i + 1))
    sleep 3
done

echo "l2tp-client: giving up after $((i - 1)) attempts"
exit 1
