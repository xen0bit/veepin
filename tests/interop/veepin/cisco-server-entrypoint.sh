#!/bin/sh
# veepin Cisco IPsec gateway for the interop harness.
#
# -setup-nat brings the TUN up with the gateway address and installs
# forwarding/NAT so the assigned client addresses are reachable. -public is given
# explicitly: the gateway's own address is hashed into the NAT-D payloads, and
# inside compose the container's eth0 address is what the client observes.
#
# SHAPE is the per-flow downstream shaping budget in bytes (0, the default, is
# off).
set -eu
SHAPE="${SHAPE:-0}"

[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }

PUBLIC=$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)

echo "veepin-cisco-server: starting on 0.0.0.0:500/4500, pool ${POOL}, public ${PUBLIC}, shape ${SHAPE}"
exec veepin serve cisco \
    -listen 0.0.0.0 \
    -public "$PUBLIC" \
    -pool "$POOL" \
    -group "$GROUP" -group-psk "$GROUP_PSK" \
    -user "$USER" -pass "$PASSWORD" \
    -banner "veepin interop gateway" \
    -domain "interop.test" \
    -tun cisco0 \
    -shape "$SHAPE" \
    -setup-nat -wan eth0
