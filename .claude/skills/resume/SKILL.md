---
name: resume
description: >-
  Read HANDOFF.md and surface the immediate next step, then STOP and wait
  for explicit confirmation before doing any work. Use at the start of a
  new session to pick up where the previous session left off.
  Pairs with the `handoff` skill.
allowed-tools: Read
disable-model-invocation: true
---

# Resume

Read `HANDOFF.md` and brief Rob on what's next. **Do not start working** —
even in auto mode — until Rob explicitly confirms.

## Steps

1. **Read `HANDOFF.md`** at the repo root.
   - If the file does not exist, say so plainly and ask Rob whether to start
     fresh or whether he expected one to be there. Do not invent a next step.

2. **Surface these specific pieces, in this order:**
   - **Timestamp** of the handoff. If it's more than 24 hours old, flag it as
     potentially stale — test status and git state may have drifted (branches
     merged, PRs reviewed, dependencies bumped).
   - **Goal.**
   - **Where We Are** + **TDD Phase** — is there a failing test awaiting an
     implementation (red), a green change awaiting refactor, or nothing in flight?
   - **Test Status** — unit / lint / which integration tiers were run vs `not run`.
   - **Awaiting Sign-Off / Decision** and **Open Questions**, if present.
   - **Immediate Next Steps → step 1** (state it verbatim).
   - **Critical Gotchas**, if present.

3. **Stop and ask for confirmation.** Use this exact framing:
   > "Ready to proceed with step 1? (yes / different step / let's talk first)"

4. **Do not begin work until Rob confirms.** Auto mode does not override this.

## Don't

- Don't summarize the entire `HANDOFF.md`. Surface only the fields above.
- Don't quietly start work because step 1 seems obvious.
- Don't invent missing fields. If a section is missing or empty, say so explicitly.
- Don't re-run `make test` / `make lint` or any integration tier during resume —
  trust the handoff's recorded status. Rob can ask for a fresh check if he wants one.
