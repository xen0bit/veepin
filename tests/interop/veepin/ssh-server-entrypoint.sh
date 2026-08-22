#!/bin/sh
# veepin SSH VPN server for the interop harness. -setup-nat assigns the gateway
# address (pool .1 = 10.200.0.1) to the TUN so the kernel answers pings to it —
# the data-path assertion. Clients authenticate with the mounted authorized key.
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
# SHAPE appends zero filler after each framed packet. OpenSSH writes the whole
# channel message to its tun device in one call, so the kernel's IP stack
# delimits the real packet by the inner header's Total Length and never sees the
# filler. That reasoning is what the shaped cell exists to check against a real
# `ssh -w` rather than against our own reader.
echo "veepin-ssh-server: serving ssh on tcp/22, gateway 10.200.0.1, shape ${SHAPE:-0}"
exec veepin serve ssh \
    -host-key /keys/host_key \
    -authorized-keys /keys/authorized_keys \
    -pool 10.200.0.0/24 \
    -shape "${SHAPE:-0}" \
    -tun tun0 \
    -setup-nat
