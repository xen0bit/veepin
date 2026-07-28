#!/bin/sh
# Reference AmneziaWG responder. Same shape as ../wireguard/server-entrypoint.sh,
# with the obfuscation parameters added to [Interface]. They are not negotiated,
# so the veepin client must be given identical values.
set -eu

export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
# amneziawg-go reads LOG_LEVEL; verbose is what makes a rejected datagram visible.
export LOG_LEVEL="${LOG_LEVEL:-verbose}"

mkdir -p /etc/amnezia/amneziawg

cat > /etc/amnezia/amneziawg/awg0.conf <<CONF
[Interface]
Address = ${SERVER_TUN_IP}/24
ListenPort = 51820
PrivateKey = ${SERVER_PRIVATE}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}

[Peer]
PublicKey = ${CLIENT_PUBLIC}
PresharedKey = ${PSK}
AllowedIPs = ${CLIENT_TUN_IP}/32
CONF

echo "awg-server: awg0 (${SERVER_TUN_IP}), H1-H4=${H1},${H2},${H3},${H4} S1=${S1} S2=${S2} Jc=${JC}"
awg-quick up awg0
awg show

echo "awg-server: ready, holding the tunnel open"
while true; do sleep 3600; done
