#!/bin/bash
# create-handoff hook v2
# Relaunch wrapper. Bridges the one gap hooks can't cross: a /clear can only
# be produced by a new process. Runs Claude; when auto-handoff.sh drops a
# relaunch sentinel, exits and starts a fresh session — which auto-resume.sh
# then briefs from HANDOFF.md. Works interactively (Rob just exits after the
# handoff commits) and for unattended headless loops (pass -p "..." args).
#
# Usage:
#   claude-loop.sh [project-dir] [-- <extra claude args>]
#   claude-loop.sh . -- -p "Resume from HANDOFF.md and do the next step"
set -uo pipefail

PROJECT_DIR="${1:-$PWD}"
shift 2>/dev/null || true
[ "${1:-}" = "--" ] && shift
cd "$PROJECT_DIR" || exit 1

while true; do
  SID="$(uuidgen)"
  export CLAUDE_CODE_SESSION_ID="$SID"   # hook children inherit this; the
                                         # sentinel path keys off it
  RELAUNCH="/tmp/claude-relaunch-${SID}"

  claude "$@" || true   # Ctrl-C / normal exit shouldn't kill the loop

  if [ -f "$RELAUNCH" ]; then
    rm -f "$RELAUNCH" "/tmp/claude-handoff-triggered-${SID}"
    echo "↻ Handoff written — relaunching with fresh context…"
    continue
  fi
  break   # no handoff pending → clean exit, stop looping
done
