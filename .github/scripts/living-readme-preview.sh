#!/usr/bin/env bash
# Show what one or more living-README regions would become if this change landed
# on main, without committing. Invoked on pull-request runs so a reviewer sees the
# matrix / throughput / benchmark diff in the job log; the working tree is
# restored afterwards.
#
# Usage: living-readme-preview.sh <label> <region> <results-file> [<region> <results-file> ...]
#
# Environment: SHA, REF (provenance footer); GITHUB_WORKFLOW (workflow name).
set -euo pipefail

label="$1"
shift

if [ "$#" -eq 0 ] || [ $(( $# % 2 )) -ne 0 ]; then
  echo "::error::living-readme-preview: expected <label> then region/file pairs" >&2
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
  echo "living-readme: $label already up to date on this branch."
else
  echo "::group::living-readme: $label would change when merged to main"
  git --no-pager diff -- README.md
  echo "::endgroup::"
fi

# Leave the tree as we found it; the PR itself must not carry a generated region.
git checkout -- README.md
