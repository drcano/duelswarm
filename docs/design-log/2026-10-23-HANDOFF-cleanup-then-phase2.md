# Claude Code brief — docs cleanup commit, THEN Phase 2. Read this first.

Date: 2026-10-23
For: the Claude Code session on branch `real-range`.
Author: the planning/verifier session, with Dante.

## Read first (source of truth)
1. `CLAUDE.md` (just rewritten — current)
2. `docs/design-log/2026-10-23-thesis.md`
3. `docs/design-log/2026-10-23-build-spec-to-target.md`
4. `docs/design-log/2026-10-23-HANDOFF-batch1.md`  ← your Phase 2 work is defined here
5. `docs/design-log/2026-10-23-phase1-verification.md`  ← Phase 1 was verified at source; two
   watch-items below carry into your work.
Do NOT trust any other status/handoff/spec doc; most are being deleted in Part A.

State: Phase 1 (cheat-sheet excision) is committed (`327befe`) and independently VERIFIED
(grep clean tree-wide, keeper selftests green, floor re-derives oos=0 cold on real and fresh
chains). You are doing TWO things, in order: a docs-cleanup commit (Part A), then Phase 2
(Part B). Nothing is pushed and nothing leaves `real-range` without Dante's go.

---

## PART A — docs cleanup (its OWN commit, before any Phase 2 code)

Goal: delete stale NARRATIVE docs so the tree is lean, WITHOUT touching anything load-bearing.

### Hard rules
- `.md` files only. Do NOT delete any `.jsonl`, `.txt`, `.svg`, `.png`, `.jpg`, `.html`, or
  `.log` — those are evidence/proof artifacts. Do NOT touch any subdirectory of `docs/`
  (`design-log/`, `prereg/`, `tasks/`, `research/`, `experiments/`, `mediation/`, `archive/`,
  `build-bundle/`, `ablation_trials/`, `arms_race_preserved/`).
- GREP-GUARD each candidate before removing it: 
  `grep -rn "<basename-without-.md>" --include="*.py" --include="*.md" --include="Makefile" . | grep -v "/attic/"`
  If anything OTHER than the file itself (or an attic copy) references it, SKIP that file and
  note it. This is the backstop against deleting something still wired in.
- After the deletions: `.venv/bin/python scripts/preregister.py --verify` MUST still pass
  (proves no prereg-anchored doc was removed), and `make test` MUST still be green with the
  range DOWN. If either breaks, a KEEP file was deleted — restore it.

### DELETE (vetted stale narrative; grep-guard each first)
Root: `README.md`, `SPEC.md`
docs/: `STATUS.md` `STATE.md` `STATUS_REPORT_2026-10-21.md` `STATUS_UI_REBUILD.md`
`PROJECT_STATUS.md` `HANDOFF.md` `LIVE_COUNTED_RUN_HANDOFF_2026-10-19.md` `CANONICAL_BUILD.md`
`SCOPE_AND_CLEANUP.md` `FRONTIER_MASTER.md` `LIQUID_BUILD_MASTER.md` `DUELSWARM_FULL_SPEC.md`
`DUELSWARM_LIQUID_SPEC.md` `BUILD_NOTES.md` `BUILD_NOTES_ENV_BOUNDARY.md`
`FRONTIER_LIVE_BUILD_NOTES.md` `ENGINE_REALISM_EXECUTION.md` `ENV_BOUNDARY_GATE_EXECUTION.md`
`FINAL_TOUCHES_EXECUTION.md` `FULL_LIQUID_LIVE_EXECUTION.md` `LIVE_WIRING_EXECUTION.md`
`COEVO_DYNAMICS_EXECUTION.md` `UI_UPGRADE_EXECUTION.md` `LIVE_DUEL_WRITEUP.md`
`NIGHT_BUILD_SUMMARY.md` `INDEX.md` `BRICK_STATUS.md` `T2_brick1_discovery_driven_red.md`
`T3_brick2_tiered_blue_that_fights.md` `T4_brick3_counter_offensive_blue.md`
`T5_brick4_two_sided_adaptation.md` `T6_brick5_environment_coevolution.md`
`T7_brick6_quality_diversity_instrument.md` `COUNTED_RUN_CRITERIA_DECISIONS.md`
`RED_BLUE_DOCTRINE.md` `FINDINGS.md` `BENCHMARK_RED.md` `AUDIT_BLUE_M6_M7.md`
`AUDIT_RANGE_vs_MHBENCH.md` `AUDIT_RED_vs_INCALMO.md`

### KEEP — do NOT delete (these are load-bearing or evidence)
- Governing: `CLAUDE.md`, all of `docs/design-log/`, `docs/DuelSwarm_Build_Tracker.md`
- Prereg-anchored by `scripts/preregister.py` (deleting ANY breaks `make test`):
  `docs/PREREGISTRATION.md`, `docs/COEVO_PREREGISTRATION.md`, `docs/prereg/EXP_A.md`,
  `docs/EXPERIMENT_DESIGNS.md`, `docs/PREREG_ENTERPRISE_ADAPTATION.md`, `docs/prereg.jsonl`
- Referenced by code: `docs/DUELSWARM_FALSIFICATION_REPORT.md`,
  `docs/PHASE2_ENTERPRISE_ARMS_RACE.md`, `docs/FULL_BUILD_BRIEF.md`, `docs/tasks/*`
- Results/falsification/paper/claims evidence (keep): `P1_PILOT_RESULT.md`,
  `PHASE2_ARMS_RACE.md`, `COEVO_RESULTS.md`, `EXPERIMENT_reasoning_vs_recall.md`,
  `AUTONOMY_MEMORY_BUILD_RESULT.md`, `DUELSWARM_PREREGISTRATION_FALSIFICATION.md`,
  `FALSIFICATION_REPORT_V3.md`, `COEVO_PREREGISTRATION_AMENDMENT_DRAFT.md`,
  `COEVO_PREREGISTRATION_AMENDMENT_B_DRAFT.md`, `CLAIM_EVIDENCE_TABLE.md`,
  `DUELSWARM_PAPER_ADDENDUM.md`, `DUELSWARM_RESEARCH_BRIEF.md`,
  `DUELSWARM_RESEARCH_GROUNDING.md`, `mhbench_openstack_setup.md`, `TAVILY_COST_CONTROL.md`,
  `gateway_residual.md`
- Everything that is not a `.md`, and every `docs/` subdirectory.

If the grep-guard flags a DELETE candidate as still-referenced, keep it and say so. If you find
an obviously-stale `.md` I did not list, apply the same principle (stale status/handoff/
execution/spec/brick narrative goes; governing/prereg/code-referenced/evidence stays) and note it.

### Commit (Part A)
Message: `docs: retire stale narrative (governing docs live in docs/design-log/)`
Body: list what was removed + the grep-guard/`preregister.py --verify`/`make test` results.
A fresh short README is a submission-time (Phase 7) task, not now.
Commits are authored `Dante Cano <drcano@ucsd.edu>`; nothing pushed.

---

## PART B — Phase 2 (one attacker engine), per the batch-one handoff

Execute Phase 2 exactly as `docs/design-log/2026-10-23-HANDOFF-batch1.md` and the build spec
define it (fold the belief machinery `env_state` + `attack_graph_service` + the anti-beeline/
vantage logic of `run_red_frontier_loop` into the one autonomous agent `live_agent.run_red_agent`
as situational awareness, not a menu; extract `tier_call`/`real_struts_foothold`/`_own`/`_gw`/
`live_recon_scan` from `live_swarm`; fold `live_red`'s booted-range executors in; keep `red_recon`
as the dry mode). Same guardrails as batch one: no new modules, move/extract don't re-implement;
nothing hardcoded on the live path; nothing advances on a self-report; commit per phase with the
source-level done-check in the message.

Done (source): exactly one red driving-loop in `swarm/` (import graph); objective-blind (no
map/scope/crown in the prompt; belief grows only from discovery events); the enterprise multi-hop
case still reaches the crown at depth >=2 from a non-entry vantage.

Two watch-items from the Phase 1 verification that Phase 2 OWES:
1. `scripts/wall.py` currently drives the dry anti-beeline red, so `blocked==0` and the wall no
   longer exercises the gate BLOCKING an out-of-scope attempt (it was honestly deferred here).
   Phase 2 must wire the adversarial oos-probe back so the wall re-derives "red attempted oos AND
   the gate blocked it," not only "0 oos executed." Do not leave this a trivial pass.
2. (Phase 4, noted now so it is not lost) `swarm/live_weapon.exploit_weblogic` still calls
   `subprocess.run(["docker","exec",...])` directly — that is a second effect site the Phase 4
   one-effect-path grep must catch and route through the single gate-dispatched primitive.

## STOP after Phase 4
Do batch one only (Phases 2, 2.5, 3, 4). STOP at the end of Phase 4 and report per-phase
source-level done-checks for verification. Do NOT begin Phase 5, 3.5, or 6.
