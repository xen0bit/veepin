#!/bin/sh
# Reference OpenSSH client: `ssh -w 0:0 -N` opens a layer-3 tunnel to the veepin
# server (no remote command, tunnel only). It then configures the local tun0 and
# holds the session; the harness pings the server's tunnel gateway. Retries until
# the server answers.
set -u
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
cp /keys/client_key /tmp/ck && chmod 600 /tmp/ck

SRV="${SERVER:-veepin-ssh-server}"
echo "ssh-client: connecting to $SRV"
i=1
while [ "$i" -le 40 ]; do
    ssh -w 0:0 -N -i /tmp/ck \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o Tunnel=point-to-point -o ExitOnForwardFailure=yes \
        -o ServerAliveInterval=5 -o ConnectTimeout=5 \
        root@"$SRV" &
    sshpid=$!

    j=0
    while ! ip link show tun0 >/dev/null 2>&1; do
        sleep 0.5; j=$((j + 1))
        [ "$j" -lt 20 ] || break
    done
    if ip link show tun0 >/dev/null 2>&1; then
        ip addr add 10.200.0.2/30 dev tun0 2>/dev/null || true
        ip link set tun0 up
        echo "ssh-client: tun0 up, holding tunnel"
        wait "$sshpid"
    else
        kill "$sshpid" 2>/dev/null || true
    fi
    echo "ssh-client: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
