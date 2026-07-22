#!/bin/sh
# Drop the removed unit from systemd's view. Instances the admin enabled are
# their own to disable; removal does not stop a running VPN out from under
# its users beyond what package removal itself does.
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
