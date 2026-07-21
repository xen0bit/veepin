#!/usr/bin/env bash
# Show what a living-README region would become if this change landed on main,
# without committing. Invoked on pull-request runs so a reviewer sees the matrix
# or benchmark diff in the job log; the working tree is restored afterwards.
#
# Usage: living-readme-preview.sh <region> <results-file>
#
# Environment: SHA, REF (provenance footer); GITHUB_WORKFLOW (workflow name).
set -euo pipefail

region="$1"
results="$2"

go run ./cmd/livingreadme \
  -region "$region" \
  -in "$results" \
  -sha "${SHA:-}" \
  -ref "${REF:-}" \
  -workflow "${GITHUB_WORKFLOW:-ci}"

if git diff --quiet -- README.md; then
  echo "living-readme: $region region is already up to date on this branch."
else
  echo "::group::living-readme: $region region would change when merged to main"
  git --no-pager diff -- README.md
  echo "::endgroup::"
fi

# Leave the tree as we found it; the PR itself must not carry a generated region.
git checkout -- README.md
