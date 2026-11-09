#!/usr/bin/env bash
# Run one CI command and mirror its useful failure lines into the check run.
#
# Why this exists: the raw job log is served from a host that is not reachable
# from every environment (and it is large), while check-run annotations are
# available from the REST API and the run summary. A failing step that says
# only "Process completed with exit code 101" costs a whole CI cycle to
# diagnose; the failing lines cost nothing.
#
# Usage: scripts/ci-annotate.sh <title> <command> [args...]
set -uo pipefail

name="${1:-step}"
shift

log="$(mktemp "${RUNNER_TEMP:-/tmp}/ci-step.XXXXXX.log")"
"$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}

if [ "$status" -ne 0 ]; then
  # One annotation per matching line, capped: annotations are a pointer to the
  # first thing that went wrong, not a replacement for the log.
  grep -nE '^(error(\[[A-Za-z0-9]+\])?:|Diff in|test .* FAILED|failures:|--- |thread .* panicked|note: (the )?match)' \
    "$log" | head -25 | while IFS= read -r line; do
    printf '::error title=%s::%s\n' "$name" "$line"
  done
fi

exit "$status"
