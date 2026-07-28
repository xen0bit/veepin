#!/bin/sh
# veepin AmneziaWG server for the interop harness. Identical in shape to
# wg-server-entrypoint.sh, plus the obfuscation parameters — which are not
# negotiated, so the client entrypoint must be given exactly the same values.
set -u

mkdir -p /etc/amneziawg
cat > /etc/amneziawg/awg0.conf <<CONF
[Interface]
PrivateKey = ${SERVER_PRIVATE}
Address = ${SERVER_TUN_IP}/24
ListenPort = 51820

[Peer]
PublicKey = ${CLIENT_PUBLIC}
PresharedKey = ${PSK}
AllowedIPs = ${CLIENT_TUN_IP}/32
CONF

echo "veepin-awg-server: serving on :51820, gateway ${SERVER_TUN_IP}, H1-H4=${H1},${H2},${H3},${H4} S1-S4=${S1},${S2},${S3},${S4}"
exec veepin serve amneziawg \
    -config /etc/amneziawg/awg0.conf \
    -tun tun0 \
    -type-init "$H1" -type-resp "$H2" -type-cookie "$H3" -type-trans "$H4" \
    -pad-init "$S1" -pad-resp "$S2" -pad-cookie "$S3" -pad-trans "$S4" \
    -setup-nat
