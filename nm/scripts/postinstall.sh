#!/bin/sh
# Reload NetworkManager so it picks up the new VPN type and D-Bus policy.
set -e
if [ -d /run/systemd/system ]; then
    systemctl reload NetworkManager 2>/dev/null || true
fi
exit 0
