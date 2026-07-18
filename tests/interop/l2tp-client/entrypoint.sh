#!/bin/sh
# Reference L2TP/IPsec client: strongSwan brings up the IKEv1/ESP transport SA to
# the veepin server, then xl2tpd dials it as a LAC and pppd runs the PPP session.
# Once IPCP completes, ppp0 carries the tunnel and 10.20.0.1 (the veepin server's
# gateway) is pingable across it.
set -e

[ -c /dev/ppp ] || mknod /dev/ppp c 108 0

install -d -m 755 /etc/xl2tpd /etc/ppp /var/run/xl2tpd
cp /conf/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf
cp /conf/options.l2tpd.client /etc/ppp/options.l2tpd.client
# pppd matches the MS-CHAPv2 secret on the client name; * accepts whatever server
# name veepin presents.
echo "${USER:-l2tpuser} * ${PASS:-l2tppass} *" > /etc/ppp/chap-secrets
chmod 600 /etc/ppp/chap-secrets

mkdir -p /etc/swanctl/conf.d
cp /conf/swanctl-l2tp-client.conf /etc/swanctl/conf.d/l2tp.conf

/usr/lib/ipsec/charon &
CHARON=$!

i=0
while [ ! -S /run/charon.vici ] && [ ! -S /var/run/charon.vici ]; do
    i=$((i + 1))
    [ "$i" -gt 80 ] && { echo "l2tp-client: vici socket never appeared"; exit 1; }
    sleep 0.25
done

# The veepin server may still be starting, so retry the initiation until the SA
# comes up rather than failing the run on a race.
i=1
while [ "$i" -le 40 ]; do
    swanctl --load-all >/dev/null 2>&1 || true
    if swanctl --initiate --child l2tp --timeout 20 2>&1; then
        echo "l2tp-client: IPsec transport SA up"
        break
    fi
    echo "l2tp-client: IPsec attempt $i failed; retrying in 3s"
    i=$((i + 1))
    sleep 3
done

# xl2tpd autodials the [lac veepin] section, running L2TP inside the SA.
xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf &
XL2TPD=$!
echo "l2tp-client: xl2tpd dialling the veepin LNS"

wait "$CHARON" "$XL2TPD"
