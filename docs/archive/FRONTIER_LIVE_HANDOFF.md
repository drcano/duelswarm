# Claude Code handoff — the live frontier build (close the gap to the dream)

Read this first. This package takes duelswarm from "Brick 0–6 verified **offline/
deterministic**" to the build we actually want: a **live, two-sided LLM cyber-conflict,
objective discovered not injected, with the floor holding against an uninstrumented
adversary, co-evolving across episodes, instrumented** — everything liquid except the
gate and the log.

## The diagnosis (why we're not there yet)

An independent audit confirmed Bricks 0–6 are real, tracked, and `make test` green — but
all of it is **deterministic and offline**, and here is the structural problem:

**The bricks and the live duel loop are two disconnected worlds.** The live path
(`run.py::_run_llm_duel`, reached by `make duel-agent` / `make demo`) still runs the OLD
system:
- **Red's objective is INJECTED.** `swarm/red_agent.py` builds the LLM prompt with
  `crown_host = _CTX["objective_host"]` and literally says *"OBJECTIVE: exfiltrate crown
  jewels from {crown_host} ({crown_cve})"* (around lines 484/498/521). The LLM red is told
  the target. It does not discover it.
- **The "duel" is partly scripted theater.** `_run_llm_duel` interleaves hardcoded
  `log.append("red"/"blue","reasoning",{"text": "...narrative..."})` strings and a fixed
  struts→jenkins beat sequence around the real LLM calls.
- **None of the bricks are wired in.** The discovery engine (`swarm/env_state.py`,
  `swarm/attack_graph_service.py`, `swarm/red_recon.py`), the tiered fighting blue
  (`swarm/blue_fast.py`), the LLM blue slow tier (`swarm/blue_llm.py`), co-evolution
  (`swarm/coevolve.py`, `swarm/env_coevo.py`), and the instrument (`swarm/instrument.py`)
  are all proven **standalone** and never touched by the live loop.
- **The floor is cooperative.** Enforcement is `gate.dispatch` intercepting red's tool
  calls. A real adversary doesn't call your gate. The topology isolation is real (and the
  genuine egress guarantee), but the per-action scope floor currently holds because red
  routes through the instrumented interface.
- **Confirmation is SIMULATED.** `swarm/spine.py::confirm()` is tagged `SIMULATED` with a
  `TODO(real-beacon)` — the observer is the range, not a real implant callback.

So "make it live" means: **rewire the live loop to run the bricks, discover the objective,
enforce the floor at real environment boundaries, confirm on real beacons, co-evolve, and
instrument — holding floor=0 for both actors the whole time.**

## The spec already exists — build on it, don't reinvent

Two untracked docs in the repo are an excellent, research-grounded blueprint. Task L0 tracks
them; every later task treats them as the detailed spec:
- `docs/FRONTIER_MASTER.md` — the north-star instrument (components 1–11), the
  selection-operator thesis, the demo-scale-now vs significance-later honesty line.
- `docs/research/REALISM_RED_BLUE.md` — **the implementation blueprint.** The red phase
  model (World State schema + phases 0–12 + the G1–G5 precondition gates that kill the
  spoon-feed) and the blue belief model (PICERL state machine, detection-as-Bernoulli,
  D3FEND lookup, watch-vs-contain gate). When a task says "per the blueprint," this is it.
- The existing execution briefs (`FULL_LIQUID_LIVE_EXECUTION.md`, `LIVE_WIRING_EXECUTION.md`,
  `ENV_BOUNDARY_GATE_EXECUTION.md`, `COEVO_DYNAMICS_EXECUTION.md`, `TAVILY_COST_CONTROL.md`)
  are prior scoping for individual pieces — track them (L0) and fold them into the tasks.

## Execution order (dependency chain)
- **L0** — track the blueprint + results; scaffold the acceptance-gate harness. (small, first)
- **L1 (TRUNK)** — the live discovery duel: make `_run_llm_duel` run the discovery-red +
  belief-blue bricks; remove the injected objective. Everything else branches off this.
- **L2** — the uninstrumented-adversary floor (enforce at the environment boundary; give
  red an uninstrumented channel). The intellectually central one.
- **L3** — real beacon confirmation (kill the SIMULATED responder).
- **L4** — live co-evolution arms race (fix population collapse; make the honest null a result).
- **L5** — the instrument at demo-N + the selection-operator experiment + the tail pipeline.
- **L6** — the gate kill-shot (capstone; optional).

Do them in order. Each task's acceptance gate is a piece of the dream, stated so it either
holds on a live log or it doesn't. Do not advance a task until its gates pass on a real run
(or its null is honestly recorded).

## The acceptance philosophy (the dream IS the bar)
A task is done when its gate is demonstrated **on a live Nemotron run**, computed from the
hash-chained log by a committed harness — not asserted, not shown only in a dry run. A null
(red fails to reach the crown; no arms race forms at demo N) is a **valid, reportable
outcome** — report it as a null, never fake a pass. "Demo scale now, significance later"
(FRONTIER_MASTER): build everything real at bounded N; the only thing gated by compute is
running to statistical significance.

## Non-negotiables (every task)
1. **Floor = 0 out-of-scope for BOTH actors, every episode.** `redteam/reverify_floor.py`
   (imports neither gate nor audit) re-derives `oos_executed=0` per actor on every live log.
   If a change could let the auditor and gate disagree, the change is wrong. Never weaken
   the floor; add realism on top of it.
2. **Hash chain verifies; the independent auditor re-derivation stays intact.**
3. **Nothing faked.** Real-executed or honestly-labeled `SIMULATED` (and SIMULATED shrinks
   as L3 lands). Blue never reads red's ground truth (blind mode is the real claim; oracle
   is ablation-only).
4. **Nebius-only for anything submission-valid** (`_assert_nebius_host` stays). Claude is a
   post-hackathon scale/benchmark model, never a submission run.
5. **Tavily is cache-first** (see L1 / `TAVILY_COST_CONTROL.md`) so a live co-evolution sweep
   doesn't re-look-up the same CVEs thousands of times and max the account.
6. **Branch `frontier-liquid`.** Never `v1.0-stable-floor`, never the submission build.
   Verify `git config user.email` is the `drcano` address before the first commit; follow
   the repo's `CLAUDE.md` attribution convention.
7. **`git add` everything you rely on; confirm with `git ls-files` before claiming done.**
   (The recurring untracked-work failure — do not repeat it.)
8. **`make test` green at every commit.** Add each task's live-gate check to the suite in a
   dry/offline-safe form (the live assertion runs under `make live-gates` with a key).
9. **If a gate can't pass** (no Nebius key, Docker absent, a real dependency found), record
   the honest null / blocker in `docs/BRICK_STATUS.md` and stop — don't force or fake it.

## Done when
`make duel-agent` (live Nemotron) runs a duel where red discovers its objective, blue
defends on belief without ground truth, both actors stay floor=0 enforced at the environment
boundary, state advances only on real confirmations, the run co-evolves across episodes, and
the instrument computes the curves from the live logs — with every gate re-derivable from the
hash chain by the independent auditor, and every remaining limitation honestly scoped in
`docs/BRICK_STATUS.md`.
