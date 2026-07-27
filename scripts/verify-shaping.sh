#!/bin/sh
# Verify that a stock VPN client tolerates veepin's downstream flow shaping.
#
# Run this ON THE CLIENT DEVICE, with the tunnel up, against the server's
# tunnel address (the pool's first host):
#
#     ./verify-shaping.sh 10.10.10.1
#
# See doc/verifying-shaping.md for the server invocations and for what to do
# with the result. This is deliberately POSIX sh whose only dependency is ping,
# so it runs on a macOS terminal, an Android shell and a Windows Git Bash
# without anything being installed — the three platforms whose stock VPN clients
# are the ones actually worth testing.
#
# The checks are ordered by what they rule out. Check 1 failing means the tunnel
# is not up; checks 2-4 failing while 1 passes is the interesting case, because
# it is the quiet failure a casual `ping -c1` would call success: the tunnel
# works but padded packets are dropped at size.
set -u

TARGET="${1:-}"
MTU="${2:-1400}"

if [ -z "$TARGET" ]; then
    echo "usage: $0 <server-tunnel-address> [inner-mtu]" >&2
    echo "  e.g. $0 10.10.10.1" >&2
    exit 2
fi

# Three ping dialects, and they disagree on every flag that matters here.
#   iputils (Linux/Android):  -c N  -s BYTES  -M do        -i SECS
#   BSD (macOS):              -c N  -s BYTES  -D           -i SECS (>=0.1 unprivileged)
#   Windows ping.exe:         -n N  -l BYTES  -f           (no interval)
case "$(uname -s 2>/dev/null || echo Windows)" in
    Darwin|*BSD*)               DIALECT=bsd ;;
    Linux)                      DIALECT=iputils ;;
    CYGWIN*|MINGW*|MSYS*|Windows) DIALECT=windows ;;
    *)                          DIALECT=iputils ;;
esac

# do_ping <count> <payload-bytes> <df:0|1> — prints ping's output, returns its
# status. The interval is left at the default everywhere: sub-second intervals
# need root on macOS, and Windows has no equivalent at all.
do_ping() {
    _count="$1"; _size="$2"; _df="$3"
    case "$DIALECT" in
        windows)
            if [ "$_df" -eq 1 ]; then
                ping -n "$_count" -l "$_size" -f "$TARGET" 2>&1
            else
                ping -n "$_count" -l "$_size" "$TARGET" 2>&1
            fi ;;
        bsd)
            if [ "$_df" -eq 1 ]; then
                ping -c "$_count" -s "$_size" -D "$TARGET" 2>&1
            else
                ping -c "$_count" -s "$_size" "$TARGET" 2>&1
            fi ;;
        *)
            if [ "$_df" -eq 1 ]; then
                ping -c "$_count" -s "$_size" -M do "$TARGET" 2>&1
            else
                ping -c "$_count" -s "$_size" "$TARGET" 2>&1
            fi ;;
    esac
}

# lossless reports whether ping's output shows no loss, in any of the three
# dialects' spellings. A zero exit status is not sufficient: some pings return 0
# having lost most of the packets.
lossless() {
    case "$1" in
        *" 0% packet loss"*|*" 0.0% packet loss"*) return 0 ;;  # iputils, BSD
        *"(0% loss)"*)                             return 0 ;;  # Windows
        *) return 1 ;;
    esac
}

pass=0
fail=0

# run <label> <what-it-rules-out> <count> <size> <df>
run() {
    _label="$1"; _rules_out="$2"; _c="$3"; _s="$4"; _d="$5"
    printf '%-44s' "$_label"
    _out=$(do_ping "$_c" "$_s" "$_d")
    if lossless "$_out"; then
        echo "PASS"
        pass=$((pass + 1))
        return 0
    fi
    echo "FAIL"
    fail=$((fail + 1))
    echo "    rules out: $_rules_out"
    echo "$_out" | sed 's/^/    | /'
    return 1
}

echo "veepin shaping verification against $TARGET (inner MTU $MTU, $DIALECT ping)"
echo

# 1. The tunnel exists at all. If this fails nothing below is meaningful.
run "1. small ping" "the tunnel is not up" 3 56 0
tunnel_up=$?

if [ "$tunnel_up" -ne 0 ]; then
    echo
    echo "The tunnel is not carrying traffic, so the remaining checks would only"
    echo "repeat the same failure. Re-run the same server WITHOUT -shape first:"
    echo "if that also fails, this is a configuration problem, not a shaping one."
    exit 1
fi

# 2. A payload large enough that the padded packet is near the MTU. This is the
#    check that catches a client which accepts the tunnel but not padded packets
#    at size.
run "2. ping, 1200-byte payload" "padded packets are dropped at size" 3 1200 0

# 3. Don't-fragment at the MTU. Shaping pads to the inner MTU, so if the padding
#    has silently pushed packets past what the path carries, this is where it
#    shows: the reply stops coming rather than arriving fragmented. 28 octets is
#    the IPv4 header plus the ICMP header, which the payload size excludes.
run "3. ping, DF set at the MTU" "the path MTU shrank under the padding" \
    3 "$((MTU - 28))" 1

# 4. Enough packets to see intermittent loss. A single ping passing while one in
#    twenty is dropped looks like success and is not. This is the slow one — the
#    interval is left at the default because sub-second intervals need root on
#    macOS — so it is last, and everything above has already reported.
run "4. 100 packets, loss counted" "intermittent drops a single ping would miss" \
    100 1200 0

echo
if [ "$fail" -eq 0 ]; then
    echo "All $pass checks passed: this client tolerates padded packets."
    echo "Add it to the table in doc/verifying-shaping.md and open a PR."
    exit 0
fi

echo "$fail of $((pass + fail)) checks failed."
echo
echo "If check 1 passed and the others did not, this is the quiet failure:"
echo "the client accepts the tunnel but not padded packets at size. Shaping"
echo "must stay opt-in for this protocol. Do NOT 'fix' it by lowering the"
echo "padding target -- a smaller target leaves size classes standing, which"
echo "is the signal the whole feature exists to remove."
exit 1
