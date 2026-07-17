#!/bin/sh
# veepin SSH VPN client for the interop harness. It opens the tun@openssh.com
# forwarding channel to the veepin server and forwards IP over a userspace TUN.
# -full-tunnel=false brings up the /30 point-to-point link so a ping to the peer
# (10.200.0.1) crosses the tunnel. Retries until the server answers.
set -u
mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
echo "ssh-client: connecting to ${SERVER}"
i=1
while [ "$i" -le 40 ]; do
    veepin connect ssh \
        -server "$SERVER" -user root \
        -identity /keys/client_key -insecure \
        -address 10.200.0.2/30 -peer 10.200.0.1 \
        -tun tun0 -full-tunnel=false
    echo "ssh-client: attempt $i failed; retrying in 3s"
    i=$((i + 1))
    sleep 3
done
exit 1
