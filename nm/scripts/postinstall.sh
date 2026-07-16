#!/bin/sh
# Reload NetworkManager so it picks up the new VPN type and D-Bus policy.
set -e
if [ -d /run/systemd/system ]; then
    systemctl reload NetworkManager 2>/dev/null || true
fi

# The project was renamed from ikennkt to veepin, and the D-Bus name changed with
# it (org.freedesktop.NetworkManager.ikennkt -> ...veepin). NetworkManager stores
# the old name inside each saved profile, so profiles created against the old
# package will not activate and must be recreated. Only say so if such a profile
# is actually present.
if command -v nmcli >/dev/null 2>&1; then
    if nmcli -t -f NAME,TYPE connection show 2>/dev/null | grep -q ':vpn$'; then
        if nmcli -t -f vpn.service-type connection show 2>/dev/null | grep -q 'ikennkt'; then
            cat <<'EOF'
veepin: found VPN connection profiles referencing the old ikennkt D-Bus service.
        They will not activate. Recreate them against the new service, e.g.:

          nmcli connection add type vpn con-name home-veepin ifname '*' \
            vpn-type org.freedesktop.NetworkManager.veepin \
            vpn.data 'protocol=ikev2, gateway=vpn.example.com, local-id=client.example.com'
          nmcli connection modify home-veepin vpn.secrets 'psk=<your-psk>'
EOF
        fi
    fi
fi
exit 0
