#!/bin/sh
# Reference OpenSSH client offering ONE key exchange: mlkem768x25519-sha256.
#
# The pinning is what makes this cell mean something. `ssh -w 0:0 -N` against a
# veepin pq-ssh server would pass just as happily on curve25519-sha256 if either
# end quietly stopped requiring the post-quantum kex, and a ping cannot tell the
# difference. With KexAlgorithms holding exactly one name there is no path
# through the handshake that succeeds without it, so a regression fails the cell
# instead of passing on the fallback -- the same argument sshd_config makes in
# ../sshd-pq, from the other end of the connection.
set -u
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
cp /keys/client_key /tmp/ck && chmod 600 /tmp/ck

# Fail loudly if this image ever regresses to an OpenSSH without the mechanism.
# Silently pinning a name the binary does not have would make every attempt fail
# for a reason that reads like a veepin bug.
ssh -Q kex | grep -q mlkem768x25519-sha256 || {
    echo "ssh-client-pq: FATAL: this OpenSSH has no mlkem768x25519-sha256" >&2
    exit 1
}

SRV="${SERVER:-veepin-pq-ssh-server}"
echo "ssh-client-pq: connecting to $SRV, kex pinned to mlkem768x25519-sha256"
i=1
while [ "$i" -le 40 ]; do
    ssh -w 0:0 -N -i /tmp/ck \
        -o KexAlgorithms=mlkem768x25519-sha256 \
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
        echo "ssh-client-pq: tun0 up, holding tunnel"
        wait "$sshpid"
    else
        kill "$sshpid" 2>/dev/null || true
    fi
    echo "ssh-client-pq: attempt $i ended; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
