#!/bin/bash
# create-handoff hook v2
# Auto-resume hook (SessionStart event).
# Reads the `source` field to tailor behavior, checks for HANDOFF.md, and
# injects a resume briefing via structured additionalContext JSON.
# Installed by /create-handoff.

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-.}"

# Clean up stale session flags from previous sessions
find /tmp -maxdepth 1 \( -name 'claude-handoff-triggered-*' -o -name 'claude-relaunch-*' \) -mtime +1 -delete 2>/dev/null

INPUT=$(cat)
SOURCE=$(echo "$INPUT" | jq -r '.source // "startup"')

# On compact the context was summarized, not discarded — a re-brief would be
# redundant and noisy. Skip. (SessionStart also fires on compaction.)
[ "$SOURCE" = "compact" ] && exit 0

# No handoff on disk — nothing to resume from.
[ -f "$PROJECT_DIR/HANDOFF.md" ] || exit 0

case "$SOURCE" in
    clear|fork) LEAD="Context was just cleared. A handoff exists — resume from it." ;;
    resume)     LEAD="Session resumed. Re-orient from the handoff." ;;
    *)          LEAD="Previous session handoff detected." ;;
esac

CTX="${LEAD} Read HANDOFF.md and brief on the key state before starting work: timestamp (flag if >24h stale), goal, current phase, any blockers or open questions, and step 1 of next steps. Then ask: \"Ready to proceed with step 1? (yes / different step / let's talk first)\" — do not start work until confirmed."

jq -n --arg ctx "$CTX" \
  '{hookSpecificOutput: {hookEventName: "SessionStart", additionalContext: $ctx}}'
