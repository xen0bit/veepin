#!/bin/sh
# Reload NetworkManager so it picks up the new VPN type and D-Bus policy.
set -e
if [ -d /run/systemd/system ]; then
    systemctl reload NetworkManager 2>/dev/null || true
fi

# Two past D-Bus service-name changes are baked into saved profiles, and
# NetworkManager matches a profile to a plugin by that name, so a profile written
# against an older package will not activate:
#
#   1. the project rename (…NetworkManager.ikennkt -> …NetworkManager.veepin);
#   2. the split into one VPN type per protocol (…veepin -> …veepin.<protocol>),
#      which is what put every veepin protocol directly in the "Add VPN" list.
#
# Both are told apart by the stored vpn.service-type. Only say anything if such a
# profile is actually present — the check is cheap and the message is noise
# otherwise.
if command -v nmcli >/dev/null 2>&1; then
    if nmcli -t -f NAME,TYPE connection show 2>/dev/null | grep -q ':vpn$'; then
        types=$(nmcli -t -f vpn.service-type connection show 2>/dev/null || true)

        if echo "$types" | grep -q 'ikennkt'; then
            cat <<'EOF'
veepin: found VPN connection profiles referencing the old ikennkt D-Bus service.
        They will not activate. Recreate them against the current services --
        one per protocol -- e.g.:

          nmcli connection add type vpn con-name home-veepin ifname '*' \
            vpn-type org.freedesktop.NetworkManager.veepin.ikev2 \
            vpn.data 'protocol=ikev2, gateway=vpn.example.com, local-id=client.example.com'
          nmcli connection modify home-veepin vpn.secrets 'psk=<your-psk>'
EOF
        fi

        # The umbrella service exactly, not the per-protocol names that extend it.
        if echo "$types" | grep -q 'org\.freedesktop\.NetworkManager\.veepin$'; then
            cat <<'EOF'
veepin: found VPN connection profiles using the single "veepin" service type.
        veepin now registers one VPN type per protocol, so that each appears
        directly in the "Add VPN" list, and the old umbrella type is gone --
        those profiles will not activate. Point each one at its protocol's
        service, which is the old name plus ".<protocol>":

          nmcli connection modify <name> \
            vpn.service-type org.freedesktop.NetworkManager.veepin.ikev2

        Use the protocol already in the profile's vpn.data 'protocol=' key
        (ikev2, wireguard, openvpn, sstp, ssh, anyconnect, nebula, masque,
        fortinet or l2tp); see:  nmcli -f vpn.data connection show <name>
EOF
        fi
    fi
fi
exit 0
