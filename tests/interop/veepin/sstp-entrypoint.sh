#!/bin/sh
set -eu
/veepin connect sstp \
  -server "${SERVER}" \
  -port "${PORT:-443}" \
  -user "${USER}" \
  -pass "${PASS}" \
  -full-tunnel=false
