---
name: handoff
description: >-
  Generate a comprehensive HANDOFF.md at the repo root so the next Claude Code
  session can resume cleanly without losing context or repeating work.
  Use when wrapping up a session, clearing context (/clear), taking a break,
  or handing off in-flight work.
  Captures Go build/test/lint state across the unit and per-ecosystem
  integration tiers, the active ecosystem plugin work, and TDD phase.
allowed-tools: Read, Write, Bash
disable-model-invocation: true
argument-hint: "What will the next session focus on? (optional)"
---

# Handoff

Generate `HANDOFF.md` at the repo root so a future session can resume cleanly.

This is the Snyk DepGraph CLI Extension — a Go module of per-ecosystem `SCAPlugin`
resolvers. See `AGENTS.md` for the architecture and hard rules; the handoff is a
pointer index into live state, not a restatement of `AGENTS.md`.

## Step 0 — If arguments were passed

Treat them as the focus statement for the next session. Tilt the Goal,
Immediate Next Steps, and Active Files sections toward that focus. Other
sections (Git State, Test Status, Memory Touched) stay objective regardless
of the argument.

## Step 1 — Gather objective state

Run these in parallel via Bash (don't trust your own recollection — capture fresh):

- `date '+%Y-%m-%d %H:%M %Z'`
- `git status --short`
- `git log --oneline -10`
- `git diff --stat`
- `git branch --show-current`
- `make test` — unit tests (`go test ./... -coverprofile cp.out`). Capture pass/fail and any failing package.
- `make lint` — golangci-lint. Capture clean/dirty and the first few findings.

**Integration tiers — do NOT run all five by default** (they need external toolchains: `bazel`, `python`/`uv`, `gradle`, `pnpm`, and set build tags). Run only the tier(s) whose ecosystem this session actually touched, and record which you ran vs skipped:
- `make test-python-integration`
- `make test-gradle-integration`
- `make test-pnpm-integration`
- `make test-bazel-jvm-integration`
- `make test-bazel-go-integration`

If a tier is relevant but you didn't run it, record it as `not run` in Test Status — don't guess its result.

## Step 2 — Review the conversation

Walk back through this session and identify:

- **What was accomplished** — plugins/resolvers changed, bugs fixed, rules updated.
- **Decisions made** — scope locked, approaches chosen (e.g. which ecosystem, which graph-shape).
- **Pending sign-offs** — anything Rob was asked to approve and hasn't yet.
- **Open questions** — questions raised that Rob hasn't answered.
- **Course corrections** — anything tried or assumed that turned out wrong (e.g. a mined rule that was stale/inverted).
- **TDD phase** — for any in-flight change: is there a failing test written (red), a passing implementation (green), or a refactor pending? Per `AGENTS.md`, new behavior is test-first (fail-before-pass, 3 attempts). Note where the current change sits.
- **Which ecosystem plugin(s)** are in play (`pkg/ecosystems/<name>`), and whether the change touches the shared contract (`SCAPlugin`, streaming callback, orchestrator registration) vs one plugin.

## Step 3 — Write HANDOFF.md

Use the template below. **Omit empty sections rather than padding them.**
Be specific and technical. Reference exact file paths and exact commands.

```markdown
# HANDOFF — <short focus>

_Generated <YYYY-MM-DD HH:MM TZ>_

## Goal
<1-2 sentences: what the next session should accomplish.>

## Where We Are
<Current state in prose. What's done, what's mid-flight.>

## TDD Phase
<For the active change: red (failing test written) / green (impl passing) /
refactor pending / n/a. Name the test(s) and package.>

## Test Status
- Unit (`make test`): <pass | fail: pkg/... | not run>
- Lint (`make lint`): <clean | findings: ... | not run>
- Integration tiers run this session: <e.g. python: pass; others not run>

## Git State
- Branch: <name>
- Uncommitted: <git status --short summary, or "clean">
- Recent: <top 1-3 relevant commits>

## Active Files
<Exact paths being edited, with a phrase on what each needs next.>

## Immediate Next Steps
1. <concrete first action>
2. ...

## Awaiting Sign-Off / Decision
<Only if non-empty.>

## Open Questions
<Only if non-empty.>

## Course Corrections
<Only if non-empty — things that turned out wrong, so the next session doesn't repeat them.>

## Critical Gotchas
<Only if non-empty — e.g. an ecosystem-specific invariant, a danger-zone file, a hard rule easy to violate.>

## Memory Touched
<Any memory files written/updated under
/Users/rob/.claude/projects/-Users-rob-code-a-cli-extension-dep-graph/memory/ ,
or "none".>
```

## Step 4 — Commit HANDOFF.md

This is a git repo. Auto-commit — stage **only** `HANDOFF.md`.

Commit message (Conventional Commits, per `AGENTS.md`): `docs: session handoff -- <short focus>`
Use HEREDOC format with a `Co-Authored-By` trailer matching the actual model powering this session.

If the working tree has other uncommitted changes, leave them — but flag them in the post-commit message.

## Step 5 — Tell Rob

After writing and committing:

1. Confirm `HANDOFF.md` was created (cite the commit SHA), and name the sections that matter most for a clean resume (usually Immediate Next Steps, TDD Phase, Test Status).
2. **Flag any other uncommitted changes** left in the tree.
3. If Rob paused mid-work (e.g. a failing test with no implementation yet, an un-pushed branch, an open PR awaiting review), call that out explicitly — those states are easy to lose.

## Don't

- Pad empty sections with placeholders. **Omit them.**
- Speculate. If you don't know something, write `unknown` and explain why.
- Forget the timestamp.
- Trust your memory of test/lint state — re-run `make test` / `make lint`.
- Auto-run all five integration tiers — they need external toolchains and are slow. Run only what's relevant; mark the rest `not run`.
- Duplicate content already in commits, PRs, `AGENTS.md`, or config. The handoff is a pointer index, not a re-statement.
- Leak secrets. `HANDOFF.md` is tracked in git; redact tokens (`SNYK_TOKEN`, `GH_TOKEN`) and personal data.
- Re-introduce content that was dropped or reverted during the session.
