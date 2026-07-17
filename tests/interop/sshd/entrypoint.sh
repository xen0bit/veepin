#!/bin/sh
# Reference sshd with PermitTunnel. Pre-creates and configures tun0 (10.200.0.1)
# owned by root so that when the veepin client requests remote unit 0, sshd binds
# this device; the harness then pings 10.200.0.1 across the tunnel.
set -eu
mkdir -p /dev/net /run/sshd
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
ssh-keygen -A >/dev/null 2>&1

ip tuntap add dev tun0 mode tun user root 2>/dev/null || true
ip addr add 10.200.0.1/30 dev tun0 2>/dev/null || true
ip link set tun0 up
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

echo "sshd: PermitTunnel on, tun0=10.200.0.1, waiting for veepin client"
exec /usr/sbin/sshd -D -e
