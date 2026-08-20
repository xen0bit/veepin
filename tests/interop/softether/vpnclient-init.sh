#!/bin/sh
# SoftEther's own vpnclient, driven against veepin's SoftEther server.
#
# This is the cell the README's `‡` footnote owed: the client direction has been
# proven against SoftEther VPN Server since compose.softether.yml landed, and
# the reverse -- SoftEther's own client against veepin's server -- had none.
#
# The peer is the same siomiz/softethervpn image the other two SoftEther cells
# already pin. It ships vpnserver, vpnclient and vpncmd from one build, so the
# reverse direction needed no new image at all.
#
# vpnclient is a daemon plus a management CLI, so this is a script rather than a
# command: start it, create a virtual NIC, describe the account, connect, and
# then address the NIC by hand. That last step is not a workaround -- SoftEther
# is layer 2 and assigns no address in the protocol, so a real deployment gets
# one from DHCP or static configuration inside the bridged segment, exactly as
# the l2tpv3 cells do.
set -u

: "${SERVER:?}"
: "${USER:?}"
: "${PASSWORD:?}"
HUB="${HUB:-DEFAULT}"
PORT="${PORT:-443}"
NIC="${NIC:-se}"
ACCOUNT="${ACCOUNT:-veepin}"
TUN_IP="${TUN_IP:-10.70.0.3}"
IFACE="vpn_$NIC"

vpnclient start >/dev/null 2>&1

# The management socket is not up when the process is. Poll it rather than
# sleeping a guessed interval.
ready=0
for _ in $(seq 1 50); do
    if vpncmd /CLIENT localhost /CMD About >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.2
done
if [ "$ready" -ne 1 ]; then
    echo "se-client: vpnclient never accepted management commands" >&2
    exit 1
fi

vpncmd /CLIENT localhost /CMD NicCreate "$NIC" >/dev/null || exit 1
vpncmd /CLIENT localhost /CMD AccountCreate "$ACCOUNT" \
    /SERVER:"$SERVER:$PORT" /HUB:"$HUB" /USERNAME:"$USER" /NICNAME:"$NIC" >/dev/null || exit 1
vpncmd /CLIENT localhost /CMD AccountPasswordSet "$ACCOUNT" \
    /PASSWORD:"$PASSWORD" /TYPE:standard >/dev/null || exit 1
# No AccountServerCertEnable: vpnclient does not verify the server certificate
# unless told to, and veepin's server in this cell presents a self-signed one --
# the same configuration the client-direction cell runs against SoftEther's own
# self-signed default.
vpncmd /CLIENT localhost /CMD AccountConnect "$ACCOUNT" >/dev/null || exit 1

# AccountConnect returns as soon as the attempt is queued, so the status is what
# says whether a session exists. "Retrying" is the failure this cell is most
# likely to see, and it is not an error exit anywhere -- it has to be read.
established=0
for _ in $(seq 1 60); do
    if vpncmd /CLIENT localhost /CMD AccountStatusGet "$ACCOUNT" 2>/dev/null \
        | grep -q "Session Established"; then
        established=1
        break
    fi
    sleep 1
done
if [ "$established" -ne 1 ]; then
    echo "se-client: vpnclient never established a session:" >&2
    vpncmd /CLIENT localhost /CMD AccountStatusGet "$ACCOUNT" 2>&1 >&2
    exit 1
fi

ip link set "$IFACE" up
ip addr add "$TUN_IP/24" dev "$IFACE"
echo "se-client: $IFACE = $TUN_IP, session established"

exec sleep infinity
