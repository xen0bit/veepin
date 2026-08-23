#!/bin/sh
# libreswan responder entrypoint. Kernel-XFRM IPsec driven by ipsec.conf.
#
# TCP selects the transport: unset or "no" leaves pluto listening on UDP 500 and
# 4500 as usual; "yes" additionally opens the RFC 8229/9329 TCP listener on
# 4500. The two are independent listeners in pluto, so the TCP cell can also
# turn UDP *off* (UDP=no) and prove the session could only have crossed on TCP.
set -eu

# In-tunnel, pingable address on the libreswan side (inside leftsubnet).
ip addr add 10.20.30.254/32 dev lo 2>/dev/null || true

# pluto keeps its keys in an NSS database; on a fresh container there is none.
ipsec initnss >/dev/null 2>&1 || true

set -- --config /etc/ipsec.conf --nofork --stderrlog --secretsfile /etc/ipsec.secrets
[ "${UDP:-yes}" = "yes" ] || set -- "$@" --no-listen-udp
[ "${TCP:-no}" = "no" ] || set -- "$@" --listen-tcp

echo "libreswan-server: udp=${UDP:-yes} tcp=${TCP:-no}; starting pluto"
/usr/libexec/ipsec/pluto "$@" &
PLUTO=$!

i=0
while [ ! -S /run/pluto/pluto.ctl ]; do
    i=$((i + 1))
    [ "$i" -gt 120 ] && { echo "libreswan: control socket never appeared"; exit 1; }
    sleep 0.25
done

# No `ipsec addconn` here: pluto --config already loaded every `auto=add`
# connection. Adding it a second time REPLACES the connection, which terminates
# any SA established on it -- and because the veepin client retries in a loop it
# can win that race, establish, and be torn down 0.2s later with pluto logging
# "deleting template instances" and nothing that looks like an error.
echo "libreswan-server: config loaded; ready as responder (id=vpn.example.com)"

wait "$PLUTO"
