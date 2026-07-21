#!/usr/bin/env bash
# Regenerate one or more living-README regions from a CI job's results and commit
# them back to main in a single commit. Invoked only on push-to-main runs, after
# the job's tests/benchmarks have already succeeded — so a commit here means the
# numbers it carries are real.
#
# Usage: living-readme-commit.sh <label> <region> <results-file> [<region> <results-file> ...]
#   label         short phrase for the commit message, e.g. "interop results"
#   region file   a livingreadme region and the job output it renders from; repeat
#                 to refresh several regions (e.g. the interop matrix and the
#                 interop throughput table, both from one -json stream) in one commit
#
# Environment: SHA, REF (provenance footer); GITHUB_WORKFLOW (workflow name).
set -euo pipefail

label="$1"
shift

if [ "$#" -eq 0 ] || [ $(( $# % 2 )) -ne 0 ]; then
  echo "::error::living-readme-commit: expected <label> then region/file pairs" >&2
  exit 2
fi

while [ "$#" -gt 0 ]; do
  region="$1"
  results="$2"
  shift 2
  go run ./cmd/livingreadme \
    -region "$region" \
    -in "$results" \
    -sha "${SHA:-}" \
    -ref "${REF:-}" \
    -workflow "${GITHUB_WORKFLOW:-ci}"
done

if git diff --quiet -- README.md; then
  echo "living-readme: $label already up to date; nothing to commit"
  exit 0
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git add README.md
# [skip ci] so the commit-back does not retrigger this workflow into a loop.
git commit -m "docs(readme): refresh $label from CI [skip ci]"

# The interop and benchmark workflows can both push their (disjoint) regions to
# main at once, so rebase-and-retry rather than fail on a lost race.
for attempt in 1 2 3 4 5; do
  if git pull --rebase origin "${REF:-main}" && git push origin "HEAD:${REF:-main}"; then
    echo "living-readme: pushed refreshed $label"
    exit 0
  fi
  echo "living-readme: push attempt $attempt lost a race; retrying"
  sleep $((RANDOM % 5 + 2))
done

echo "::error::living-readme: failed to push refreshed $label after retries"
exit 1
