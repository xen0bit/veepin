#!/bin/sh
# Reload NetworkManager so the removed VPN type is forgotten.
set -e
if [ -d /run/systemd/system ]; then
    systemctl reload NetworkManager 2>/dev/null || true
fi
exit 0
