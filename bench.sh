#!/usr/bin/env bash
# Run the full ikev2-go benchmark suite.
#
# Usage:
#   ./bench.sh                 # all benchmarks, default 1s each
#   ./bench.sh -benchtime 3s   # longer runs for stable numbers
#   ./bench.sh -run ESP        # only ESP data-plane benchmarks (regex on name)
#
# Any extra arguments are passed through to `go test -bench`.

set -euo pipefail

# Default: match every benchmark. Override the name filter with BENCH=...
BENCH="${BENCH:-.}"

# Pass -benchmem for allocation stats; -benchtime tunes run length.
exec go test \
    -run '^$' \
    -bench "$BENCH" \
    -benchmem \
    "${@:--benchtime=1s}" \
    ./...
