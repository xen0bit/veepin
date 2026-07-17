#!/bin/sh
# veepin SSH VPN server for the interop harness. -setup-nat assigns the gateway
# address (pool .1 = 10.200.0.1) to the TUN so the kernel answers pings to it —
# the data-path assertion. Clients authenticate with the mounted authorized key.
set -eu
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "veepin-ssh-server: serving ssh on tcp/22, gateway 10.200.0.1"
exec veepin serve ssh \
    -host-key /keys/host_key \
    -authorized-keys /keys/authorized_keys \
    -pool 10.200.0.0/24 \
    -tun tun0 \
    -setup-nat
