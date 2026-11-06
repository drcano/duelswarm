# duelswarm — session handoff (read me first)

Date: 2026-10-23, ~16:30 PT. For: a fresh planning/verifier chat picking this up. This chat got
context-heavy; nothing is lost — everything below is committed in the repo.

## Your role in this project
You are the PLANNER / VERIFIER for duelswarm, working with Dante. You do NOT build. Dante hands all
building to a separate Claude Code session; you read the tree at source, verify claims cold, write
the plans/design-logs, and keep the build honest. Never hand Dante a task you can do yourself;
exhaust your tools before handing anything back; always go to the primary source and verify, never
trust a summary or a build report.

## Where everything lives
- Repo (authoritative, committed): `<repo>`, branch `real-range`, on
  Dante's machine, reached through the device bridge (`mcp__remote-devices__*`). The connected
  folder is `<repo>/dev`.
- The bridge is FILE-ONLY (no shell on his machine): `device_list_dir`, `device_stage_files`
  (repo → container so you can Read), `device_commit_files` (container → repo; outputs must be
  under `/mnt/user-data/outputs/`; use `force:true` to overwrite a doc you own). To read current
  code, stage it first. The memory folder (`~/.claude/.../memory`) is NOT grantable via the bridge.
- Scratchpad (ephemeral): the session scratchpad dir. Memory (persistent governing notes): the
  session's memory directory.
- Governing docs, in `docs/design-log/` (READ IN THIS ORDER):
  1. `2026-10-23-thesis.md` — the North Star (what the range is FOR; the epistemics).
  2. `2026-10-23-build-spec-to-target.md` — the 7-phase plan, grounded in a line-by-line read of
     the whole non-attic tree on 2026-10-23.
  3. `2026-10-23-HANDOFF-batch1.md` — the brief a fresh Claude Code session is executing now.
  4. `docs/DuelSwarm_Build_Tracker.md` — the claims board, updated 2026-10-23.
  `CLAUDE.md` and older status/handoff/CANONICAL/SCOPE docs are STALE — do not trust them.

## The target (one paragraph; full statement in the thesis doc)
A sandbox that is a faithful snapshot of future AI-vs-AI warfare. Red and blue are each autonomous
LLM agents with the full real toolkit a current operator has PLUS the ability to author new tools
at runtime, run as co-evolving POPULATIONS (one engine per side, many concurrent instances —
duelSWARM) that constantly adapt. Underneath them sits the only non-adaptive part: a deterministic
floor that mediates every action against a fixed scope, and a tamper-evident hash-chained log.
The range exists to watch what a fixed floor does to an endlessly-adapting attacker and defender,
and to find where the harm goes once it can't go through the front door. It is built to be proven
wrong. Four open claims (floor-as-selection-pressure; attacker migrates to allowed-action chains;
one-bit-no-gradient beats a monitor; harm concentrates in the seams between floors).

## State of play (where we are RIGHT NOW)
- A full re-audit on 2026-10-23 found the earlier "converged on one red" claim was overstated: the
  hard parts are built and clean, but it is NOT yet one engine (5 reds, ~4 blues, 2–3 ranges still
  on disk; the cheat-sheet lineage `red_agent`/`red_tools`/`run.py`/`eval.py`/orchestrator prompts
  still present and imported). `attic/` holds ~70 already-discarded files; never revive them.
- The target was locked with Dante (autonomous tool-authoring agents; Sliver C2; MHBench-real
  range; two co-evolving populations; penetration-is-a-result; readiness-is-source-not-suite).
- Batch one (phases 1, 2, 2.5, 3, 4 — convergence + floor + Sliver C2) was handed to a fresh
  Claude Code session via `2026-10-23-HANDOFF-batch1.md`. It is scoped to STOP after Phase 4 and
  report. The three real builds (Phase 5 MHBench-real range, 3.5 tool authoring, 6 two-population
  co-evolution) are held for review.
- IMMEDIATE NEXT VERIFIER ACTION: when the Claude Code session reports batch one, verify its
  done-conditions AT SOURCE (stage the changed files; grep the cheat-sheet is gone; confirm one-of-
  each by import graph; cold `reverify_floor`; the gate verb-axis self-test; the Sliver beacon is
  real + gate-mediated + logged). Only then green-light batch two. Do not take the CC report's word
  for it — re-derive.

## Decisions locked (do not relitigate)
- Both sides are the AUTONOMOUS AGENT substrate (`live_agent`/`live_blue_agent`), NOT a frontier
  menu; the belief layer feeds awareness, it does not cap actions.
- C2 = Sliver, real on the wire, real server container on red's infra net; ONE shared C2 for v1 but
  the handle is per-actor-ready. v1 defaults: native beacon/jitter only (evasive tricks later); ALL
  post-foothold delivery (incl. authored tools) goes down the implant session (one effect path).
- Genome = `{prompt, memory, authored_tools}`; co-evolution selects over strategy AND invented
  tools. Fitness telemetry-sourced, never self-report.
- Logs: full reasoning + activity for both sides, hash-linked parallel store (blob in store, hash
  in the chain). Storage is not a constraint.
- Readiness = re-derivation at source + one-of-each + nothing-hardcoded + falsification bites. A
  green `make test` is a smoke only and NEVER the done-signal; a module's selftest passing is never
  a reason to keep it (this is what caused the bloat).
- Penetration is a RESULT to study, not a build failure. The floor holding is the experiment. The
  one non-negotiable is a faithful instrument (every action mediated + re-derivable). The only real
  build failure is an UNRECORDED effect.
- DEFERRED (not v1): multiple same-actor coordinated instances + distinct independent APTs that
  cooperate or fight. Land one stable attacker population first.

## Verification method (how this chat read the tree, so you can too)
- Stage files from the repo via the bridge into `/mnt/user-data/uploads/dev/duelswarm/...`, then
  Read locally and grep. CAVEAT: that uploads copy is the PRE-attic snapshot — it still contains
  stale copies of files now in `attic/`. Exclude attic'd names (derive them from a
  `device_list_dir` of `attic/` recursive) or your greps will count discarded modules as live.
- Read offensive/attacker code YOURSELF in-context. Subagents trip the `[cyber]` classifier on fresh
  API calls carrying offensive-security code; this chat lost two parallel agents that way. Defensive/
  infra/analytical clusters are fine to delegate.
- Commit design-log docs you author back to the repo via `device_commit_files` (source under
  `/mnt/user-data/outputs/`). Nothing pushed, nothing off `real-range`, without Dante's go.

## Standing constraints (from Dante's preferences)
Primary source always; never trust a fetch summary. Capture design discussions in dated
`docs/design-log/` Markdown. No em-dashes or AI-style punctuation in APPLICATION documents (resume/
outreach); plain, confident, explain-simply writing everywhere. Don't build — hand to Claude Code.
Git author note on commits: author `Dante Cano <drcano@ucsd.edu>`.

## Research references (primary sources)
- Incalmo (attacker-infra/C2 basis; we chose Sliver to improve on its Caldera approach):
  arXiv:2501.16466, Singer et al.
- UK AISI cyber alignment assessment (the ungated-egress failure the floor answers):
  https://www.anthropic.com/research/alignment-assessment-ukaisi
- MHBench IR + fixtures are vendored under `third_party/mhbench/` (MIT © 2025 Brian Singer).

## Hackathon / deadline context
Nebius × NVIDIA Global AI Hackathon, Devpost deadline Oct 30 2026. The reviewer artifact rides on
the consolidated engine.
