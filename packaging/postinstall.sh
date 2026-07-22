#!/bin/sh
# Make the freshly installed veepin@.service template visible to systemd.
# Guarded: containers and non-systemd systems install fine without it.
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
