#!/bin/sh
# strongSwan Cisco IPsec responder entrypoint (veepin client -> here).
#
# Aggressive Mode with a pre-shared key is refused by charon unless it is told
# to allow it. The option's name is strongSwan's own editorial comment on the
# mode; every deployment of this protocol has to set it, which is why the
# interop harness does too.
set -e

mkdir -p /etc/strongswan.d
cat > /etc/strongswan.d/aggressive.conf <<'CONF'
charon {
    i_dont_care_about_security_and_use_aggressive_mode_psk = yes
}
CONF

# In-tunnel, pingable address on the strongSwan side (inside local_ts).
ip addr add 10.20.30.254/32 dev lo 2>/dev/null || true

/usr/lib/ipsec/charon &
CHARON=$!

i=0
while [ ! -S /run/charon.vici ] && [ ! -S /var/run/charon.vici ]; do
    i=$((i + 1))
    [ "$i" -gt 80 ] && { echo "strongswan: vici socket never appeared"; exit 1; }
    sleep 0.25
done

swanctl --load-all
echo "strongswan-cisco-server: config loaded; ready as an Aggressive Mode + XAuth responder"

wait "$CHARON"
