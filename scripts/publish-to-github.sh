#!/usr/bin/env bash
# Create the GitHub remote for this repository and push.
#
# `gh` was not available when this repository was created, so the push was not
# performed. Run this once you have a remote.
#
#   ./scripts/publish-to-github.sh <github-user> [repo-name]
#
# Requires: git, plus either `gh` (authenticated) or an SSH key on GitHub.
set -euo pipefail

USER_NAME="${1:-}"
REPO="${2:-netrocket}"

if [[ -z "$USER_NAME" ]]; then
  echo "usage: $0 <github-user> [repo-name]" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

if command -v gh >/dev/null 2>&1; then
  echo "creating https://github.com/$USER_NAME/$REPO via gh"
  gh repo create "$USER_NAME/$REPO" --public --source=. --remote=origin --push \
    --description "Per-application bandwidth shaping for Windows, in Rust. Fast, light, and does not waste bandwidth."
else
  echo "gh not found: creating the remote with plain git (the repo must already exist on GitHub)"
  git remote remove origin 2>/dev/null || true
  git remote add origin "git@github.com:$USER_NAME/$REPO.git"
  git branch -M main
  git push -u origin main
fi

echo
echo "done. next:"
echo "  1. edit Cargo.toml  [workspace.package] repository = https://github.com/$USER_NAME/$REPO"
echo "  2. check the CI badge in README.md"
