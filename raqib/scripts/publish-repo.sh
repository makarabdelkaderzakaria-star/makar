#!/usr/bin/env bash
#
# Publish Raqib as a standalone repository under a new name.
#
#   ./scripts/publish-repo.sh <new-repo-name> [public|private]
#
# It builds a clean tree (no node_modules, no dist), commits it with a full
# history of its own, creates the repository and pushes. Nothing is pulled
# from the network except the repository you asked for.
#
set -euo pipefail

NAME="${1:-}"
VISIBILITY="${2:-public}"

if [[ -z "$NAME" ]]; then
  echo "usage: $0 <new-repo-name> [public|private]" >&2
  exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "the GitHub CLI is required: https://cli.github.com" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "raqib: staging a clean copy in $STAGE"
tar -C "$ROOT" \
  --exclude=node_modules \
  --exclude=dist \
  --exclude=.git \
  --exclude=bench/results.json \
  -cf - . | tar -xf - -C "$STAGE"

cd "$STAGE"
git init -q -b main
git add -A
git -c user.name="$(gh api user -q .login 2>/dev/null || echo raqib)" \
    -c user.email="$(gh api user -q .email 2>/dev/null || echo raqib@users.noreply.github.com)" \
    commit -q -m "Raqib 0.1.0 — a light, offline reverse-engineering observatory

An MCP server, a CLI and a local console that inspect ELF and PE binaries,
JavaScript and Electron applications, ASAR archives and Chromium-family source
trees without executing the target and without touching the network.

- zero runtime dependencies; the shipped file is 224 KB
- no network access at any point, including setup and assets
- evidence model with content-derived identity and explicit limitations"

OWNER="$(gh api user -q .login)"
REMOTE="https://github.com/${OWNER}/${NAME}.git"

echo "raqib: creating ${OWNER}/${NAME} (${VISIBILITY})"
gh repo create "${OWNER}/${NAME}" --"${VISIBILITY}" \
  --description "A light, offline reverse-engineering observatory: MCP server, CLI and local console for ELF/PE, JS/Electron apps, ASAR and Chromium forks." \
  --source=. --remote=origin --push

echo
echo "raqib: published → https://github.com/${OWNER}/${NAME}"
echo "raqib: clone it with  git clone ${REMOTE}"
