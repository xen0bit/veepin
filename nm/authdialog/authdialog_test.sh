#!/bin/sh
# Non-interactive tests for the auth-dialog: feed NM's stdin protocol and check
# the emitted secrets. The interactive GTK path needs a user, so it is not
# covered here. Usage: authdialog_test.sh <path-to-binary>
set -eu

BIN="${1:-./bin/nm-veepin-auth-dialog}"
SVC=org.freedesktop.NetworkManager.veepin
fail() { echo "FAIL: $1" >&2; exit 1; }

# 1. PSK-only, saved secret -> emits psk value, no password.
out=$(printf 'DATA_KEY=gateway\nDATA_VAL=g\nSECRET_KEY=psk\nSECRET_VAL=s3cret\nDONE\n' \
        | timeout 5 "$BIN" -s "$SVC" -u UID -n test)
echo "$out" | grep -qx psk    || fail "no psk key in output"
echo "$out" | grep -qx s3cret || fail "no psk value in output"
echo "$out" | grep -qx password && fail "password emitted without a user"
echo "ok: psk-only"

# 2. EAP (user set) -> emits psk and password.
out=$(printf 'DATA_KEY=user\nDATA_VAL=alice\nSECRET_KEY=psk\nSECRET_VAL=s\nSECRET_KEY=password\nSECRET_VAL=wonderland\nDONE\n' \
        | timeout 5 "$BIN" -s "$SVC")
echo "$out" | grep -qx password   || fail "no password key for EAP"
echo "$out" | grep -qx wonderland || fail "no password value for EAP"
echo "ok: eap"

# 3. WireGuard, saved private key -> emits private-key, and never psk/password.
out=$(printf 'DATA_KEY=protocol\nDATA_VAL=wireguard\nSECRET_KEY=private-key\nSECRET_VAL=mypriv\nDONE\n' \
        | timeout 5 "$BIN" -s "$SVC")
echo "$out" | grep -qx private-key || fail "no private-key key for wireguard"
echo "$out" | grep -qx mypriv      || fail "no private-key value for wireguard"
echo "$out" | grep -qx psk      && fail "psk emitted for a wireguard connection"
echo "$out" | grep -qx password && fail "password emitted for a wireguard connection"
echo "ok: wireguard"

# 4. Wrong service -> refuses (non-zero).
if printf 'DONE\n' | timeout 5 "$BIN" -s org.freedesktop.NetworkManager.other; then
    fail "accepted a foreign service"
fi
echo "ok: foreign-service refused"

echo "PASS: auth-dialog non-interactive paths OK"
