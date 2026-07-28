#!/bin/sh
# Provision the SoftEther SSTP server for the interop test. The siomiz image
# auto-generates a random user and does not enable SSTP, so we drive vpncmd to a
# deterministic state: SSTP on, a known MS-CHAPv2 user, and SecureNAT (which
# supplies a DHCP pool and a pingable virtual gateway at 192.168.30.1).
#
# It runs as a sidecar against the already-started server container and exits 0
# once provisioning succeeds, so the test can gate on its completion.
set -eu

SERVER="${SERVER:-server}"
SPW="${SPW:-sstpadmin}"
USER="${SSTP_USER:-sstpuser}"
PASS="${SSTP_PASS:-sstppass}"
HUB="${HUB:-DEFAULT}"

# Wait for the management port to answer.
i=1
while [ "$i" -le 40 ]; do
    if vpncmd "$SERVER" /SERVER /PASSWORD:"$SPW" /CMD ServerInfoGet >/dev/null 2>&1; then
        break
    fi
    echo "sstp-init: waiting for VPN server ($i)..."
    i=$((i + 1))
    sleep 2
done

# Enable the SSTP clone server.
vpncmd "$SERVER" /SERVER /PASSWORD:"$SPW" /CMD SstpEnable yes

# Create the user, set its password, and turn on SecureNAT. Interactive mode
# (piped) is used because the /HUB admin form of vpncmd hangs in this image.
vpncmd "$SERVER" /SERVER /PASSWORD:"$SPW" <<EOF
Hub $HUB
UserCreate $USER /GROUP:none /REALNAME:none /NOTE:none
UserPasswordSet $USER /PASSWORD:$PASS
SecureNatEnable
exit
EOF

echo "sstp-init: provisioning complete (user=$USER, SecureNAT gateway 192.168.30.1)"
