#!/bin/sh
# Provision the SoftEther VPN Server for the *native* SE-VPN interop cell.
#
# Distinct from sstp-init.sh next to it, and deliberately so: that script
# enables the SSTP clone server, which is a compatibility layer bolted onto the
# same daemon. This one touches none of that. The native protocol is what
# SoftEther's own client speaks to its own server, it is on by default on 443,
# and it is the one veepin's softether row claims.
#
# What it does need is an account to log in as -- the image invents a random
# user with a random password on first boot, which is fine for a product and
# useless for a test -- and SecureNAT, which supplies a virtual gateway at
# 192.168.30.1 that answers ARP and ICMP. That gateway is what the cell pings,
# and it is a real SoftEther data path answering, not a second veepin.
#
# It runs as a sidecar against the already-started server container and exits 0
# once provisioning succeeds, so the cell can gate on its completion.
set -eu

SERVER="${SERVER:-server}"
SPW="${SPW:-seadmin}"
USER="${SE_USER:-alice}"
PASS="${SE_PASS:-s3cret}"
HUB="${HUB:-DEFAULT}"

# Wait for the management port to answer.
i=1
while [ "$i" -le 40 ]; do
    if vpncmd "$SERVER" /SERVER /PASSWORD:"$SPW" /CMD ServerInfoGet >/dev/null 2>&1; then
        break
    fi
    echo "native-init: waiting for VPN server ($i)..."
    i=$((i + 1))
    sleep 2
done

# Interactive mode (piped) rather than the /HUB admin form, which hangs in this
# image -- the same finding sstp-init.sh records, and it is still true.
vpncmd "$SERVER" /SERVER /PASSWORD:"$SPW" <<EOF
Hub $HUB
UserCreate $USER /GROUP:none /REALNAME:none /NOTE:none
UserPasswordSet $USER /PASSWORD:$PASS
SecureNatEnable
exit
EOF

# UserCreate failing is not fatal above (vpncmd returns 0 for a duplicate), so
# assert the account exists rather than trusting the exit status. Without this
# the cell's failure mode is an authentication error that reads like a digest
# bug, which is a long way to walk to discover the user was never made.
if ! vpncmd "$SERVER" /SERVER /PASSWORD:"$SPW" <<EOF | grep -q "^User Name.*$USER"
Hub $HUB
UserGet $USER
exit
EOF
then
    echo "native-init: user $USER was not created" >&2
    exit 1
fi

echo "native-init: provisioning complete (user=$USER, SecureNAT gateway 192.168.30.1)"
