#!/bin/sh
# veepin SSH client -> reference sshd (PermitTunnel). Requests remote tun unit 0
# so sshd binds its pre-configured tun0 (10.200.0.1). -full-tunnel=false brings up
# the /30 link; the harness pings 10.200.0.1. Retries until sshd answers.
set -u
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "veepin-ssh-client: connecting to ${SERVER}"
i=1
while [ "$i" -le 40 ]; do
    veepin connect ssh \
        -server "$SERVER" -user root \
        -identity /keys/client_key -insecure \
        -address 10.200.0.2/30 -peer 10.200.0.1 -peer-unit 0 \
        -tun tun0 -full-tunnel=false
    echo "veepin-ssh-client: attempt $i failed; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
