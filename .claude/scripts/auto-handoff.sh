#!/bin/bash
# create-handoff hook v2
# Auto-handoff hook (Stop event).
# Reads context window token usage from stdin JSON (same payload the
# statusline receives). When used tokens cross a fixed threshold,
# instructs Claude to perform a full handoff before continuing.
# Installed by /create-handoff. Threshold adjustable via AUTO_HANDOFF_THRESHOLD.

THRESHOLD="${AUTO_HANDOFF_THRESHOLD:-150000}"
SESSION_ID="${CLAUDE_CODE_SESSION_ID:-unknown}"
TRIGGERED_FILE="/tmp/claude-handoff-triggered-${SESSION_ID}"

# Already triggered this session — exit silently
[ -f "$TRIGGERED_FILE" ] && exit 0

# Read context usage from stdin JSON
INPUT=$(cat)

# Try absolute token count first, fall back to computing from percentage + total
USED=$(echo "$INPUT" | jq -r '.context_window.used // empty')
if [ -z "$USED" ]; then
    PCT=$(echo "$INPUT" | jq -r '.context_window.used_percentage // empty')
    TOTAL=$(echo "$INPUT" | jq -r '.context_window.total // empty')
    if [ -n "$PCT" ] && [ -n "$TOTAL" ]; then
        USED=$(echo "$PCT $TOTAL" | awk '{printf "%.0f", $1 * $2 / 100}')
    else
        exit 0
    fi
fi

# At threshold: trigger handoff
if [ "$USED" -ge "$THRESHOLD" ] 2>/dev/null; then
    touch "$TRIGGERED_FILE"
    # Relaunch sentinel: consumed by claude-loop.sh (if installed) to start a
    # fresh context after this session exits. A hook cannot trigger /clear
    # itself; crossing the process boundary is the only way to reset context.
    touch "/tmp/claude-relaunch-${SESSION_ID}"
    USED_K=$((USED / 1000))
    THRESHOLD_K=$((THRESHOLD / 1000))
    cat <<EOF
Context checkpoint: context window has reached ~${USED_K}k tokens (threshold: ${THRESHOLD_K}k). Performance degrades past this point. To preserve session state, perform a handoff now.

Read .claude/skills/handoff/SKILL.md and follow its complete procedure — gather objective state, review the conversation, write HANDOFF.md, and commit it. Once it's committed, run /clear to continue with a fresh context: the auto-resume hook fires on SessionStart (source "clear") and will brief the next session from HANDOFF.md. (If this session was launched by claude-loop.sh, just exit instead — the wrapper relaunches with fresh context automatically.)
EOF
fi
