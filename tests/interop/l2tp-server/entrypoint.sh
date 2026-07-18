#!/bin/sh
# Reference L2TP/IPsec server: strongSwan terminates the IKEv1/ESP transport SA,
# xl2tpd terminates L2TP inside it and drives pppd. 10.30.0.1 is the LNS's PPP
# local address, which the veepin client pings across the tunnel.
set -e

[ -c /dev/ppp ] || mknod /dev/ppp c 108 0

install -d -m 755 /etc/xl2tpd /etc/ppp /var/run/xl2tpd
cp /conf/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf
cp /conf/options.xl2tpd /etc/ppp/options.xl2tpd
# pppd looks up the MS-CHAPv2 secret by (client, server) — the server name is the
# `name` in options.xl2tpd.
echo "${USER:-l2tpuser} veepin-lns ${PASS:-l2tppass} *" > /etc/ppp/chap-secrets
chmod 600 /etc/ppp/chap-secrets

mkdir -p /etc/swanctl/conf.d
cp /conf/swanctl-l2tp-server.conf /etc/swanctl/conf.d/l2tp.conf

# charon must be up with its vici socket before swanctl can load anything.
/usr/lib/ipsec/charon &
CHARON=$!

i=0
while [ ! -S /run/charon.vici ] && [ ! -S /var/run/charon.vici ]; do
    i=$((i + 1))
    [ "$i" -gt 80 ] && { echo "l2tp-server: vici socket never appeared"; exit 1; }
    sleep 0.25
done

swanctl --load-all
echo "l2tp-server: strongSwan loaded (IKEv1 PSK, transport mode, udp/1701)"

# xl2tpd listens on 1701 for the L2TP the ESP SA protects.
xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf &
XL2TPD=$!
echo "l2tp-server: xl2tpd listening on udp/1701, LNS local ip 10.30.0.1"

wait "$CHARON" "$XL2TPD"
