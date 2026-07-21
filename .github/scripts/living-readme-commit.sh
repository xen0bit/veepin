#!/usr/bin/env bash
# Regenerate one living-README region from a CI job's results and commit it back
# to main. Invoked only on push-to-main runs, after the job's tests/benchmarks
# have already succeeded — so a commit here means the numbers it carries are real.
#
# Usage: living-readme-commit.sh <region> <results-file> <human-label>
#   region        livingreadme region name, e.g. "interop" or "benchmark"
#   results-file  the job output the region is rendered from
#   human-label   short phrase for the commit message, e.g. "interop matrix"
#
# Environment: SHA, REF (provenance footer); GITHUB_WORKFLOW (workflow name).
set -euo pipefail

region="$1"
results="$2"
label="$3"

go run ./cmd/livingreadme \
  -region "$region" \
  -in "$results" \
  -sha "${SHA:-}" \
  -ref "${REF:-}" \
  -workflow "${GITHUB_WORKFLOW:-ci}"

if git diff --quiet -- README.md; then
  echo "living-readme: $region region already up to date; nothing to commit"
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
    echo "living-readme: pushed refreshed $region region"
    exit 0
  fi
  echo "living-readme: push attempt $attempt lost a race; retrying"
  sleep $((RANDOM % 5 + 2))
done

echo "::error::living-readme: failed to push refreshed $region region after retries"
exit 1
