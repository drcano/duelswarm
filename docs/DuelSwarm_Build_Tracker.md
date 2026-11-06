# DuelSwarm Build Tracker

Where the build is vs. where it's heading. The bar: every claim is either demonstrated on the real build, labeled *mechanism built — needs compute for significance*, or flagged as open speculation. Nothing faked, nothing implied-done. "Demonstrated" means re-derived cold from the raw hash chain by a checker that trusts neither the floor nor the agents — never taken from a build report, and never from a green `make test`.

Updated 2026-10-23 · branch `real-range` · local only (GitHub suspended) · Docker restored, paid frontier validation pending

> **Readiness is re-derivation at source, not a passing suite.** `make test` green is a smoke check only. The last cleanup stalled because the suite ran every module's selftest, so keeping it green made every module load-bearing — which is why the slop could not be cut. A module's selftest passing is never a reason to keep it; the trust-boundary partition decides what survives, and the suite is rebuilt to match. See `docs/design-log/2026-10-23-build-spec-to-target.md` ("What 'ready' means").

> **Governing docs (read in this order):** `docs/design-log/2026-10-23-thesis.md` (the North Star), `docs/design-log/2026-10-23-build-spec-to-target.md` (the plan, grounded in a line-by-line read of the tree on 2026-10-23), `docs/design-log/2026-10-23-HANDOFF-batch1.md` (what Claude Code is executing now). `CLAUDE.md` and older status/handoff docs are stale — do not trust them.

## Current milestone

### Target locked and planned, not yet built: one clean engine, two co-evolving tool-authoring populations, MHBench-real range, Sliver C2

A full line-by-line re-audit of the live `real-range` tree on 2026-10-23 corrected an over-optimistic prior entry. The hard parts are real and clean — the gate, hash-chained log, independent telemetry, deterministic reconciler, confirm→mutate spine, twin cold auditors, the objective-blind belief-frontier red, the full real blue toolkit (4-sensor detector, eviction ladder), the real vetted-exploit range, the vendored MHBench adapter, and the red MAP-Elites population. But they are **not yet one engine**: five red driving-loops, three-to-four blue loops, and two-to-three range generators are still on disk, and the cheat-sheet lineage (`red_agent`, `red_tools`, `run.py`, `eval.py`, the orchestrator prompts) is still present and still imported. The prior "converged on one red" claim was the frontier red *existing*, not the duplicates being *gone*.

The target was also sharpened with Dante into its final form: the sandbox is a **faithful snapshot of future AI-vs-AI warfare**. Red and blue are each autonomous agents with the full real toolkit a current operator has **plus the ability to author new tools at runtime**, and they are **co-evolving populations** (duelSWARM: one engine per side, many concurrent instances) that constantly adapt. Red operates from **real Sliver C2 infrastructure**. The range is **MHBench topology on real vetted-exploit images**. Everything — including full agent reasoning — is logged to a hash-linked store. A penetration is a **result to study, not a build failure**; the floor holding is the experiment, not a build gate; the one non-negotiable is a **faithful instrument** (every action mediated + re-derivable).

A 7-phase build spec and a batch-one handoff to a fresh Claude Code session were produced (see Roadmap). Nothing in the consolidation or the two big builds is done yet.

## Fidelity at a glance

- **Demonstrated (capabilities that exist and re-derive cold):** 8
- **Partial:** 1
- **Needs compute:** 5
- **Speculation:** 3
- **Consolidation + the two mandate builds:** planned, not started (batch one handed to Claude Code 2026-10-23)

## ● Demonstrated — claim matches the build

(These are capabilities that exist in the tree today and re-derive cold. They survive the consolidation; the work ahead is to make them the ONE path, not to rebuild them.)

**building-duelswarm** — *The exploits are real and execute against real containers, through the floor.*
Backed by: Live gated MSF pops — Apache (`uid=1(daemon)`) + GitLab (`uid=1000(git)`), `fidelity=real`; 5 T1 in `vetted.json`; chains re-derived. Struts CVE-2017-5638 grounds a real MSF session end-to-end on the enterprise range.

**the-floor** — *Floor is structural segmentation, not a parser; `oos_executed=0`.*
Backed by: `gate.py`, `prove_env_boundaries --live`, `oos=0` re-derived cold under every live MSF pop, held at 19-host enterprise scale by `reverify_floor`. The egress parser is best-effort by design; the segmentation is the enforcement; `oos_tcp_reaches` is MEASURED, not asserted zero.

**where-the-floor-lives** — *Enforce at the boundary the action crosses, not its description.*
Backed by: `prove_env_boundaries --live` (parser off → `oos_reaches=0`); MSF fires only via `gate.dispatch`. Strongest, most honest, LLM-independent claim.

**the-enterprise-is-real-terrain** — *A move-space enterprise (branching, decoys, multi-entry), not a corridor.*
Backed by: `range_gen.generate_range(scale="enterprise")` (19 hosts/6 segments, 2 real entries, 2 branching crown routes, 9 decoys, reachable trap + isolated OOS); boots ~6s. NOTE: this is the bespoke pool-driven generator; the mandate ("range based on MHBench") is a build ahead — marry this with `topo_to_compose` (the MHBench adapter) on real images.

**primary-record-is-telemetry** — *The targets' own hash-chained telemetry decides what happened, not the harness.*
Backed by: `live_telemetry` + `live_truth` reconciler; foothold + laterals corroborated by destinations' own logs, flagged 0, chain verified.

**keeping-myself-honest** — *Pre-register + hash, report to the log, null stays a null.*
Backed by: `preregister.py` (anchor seq=17), `verify_live_run.py`, `degeneracy.py`; the verifier re-derives every pop cold.

**no-oracle-either-side** — *Red arrives blind; blue reads only its sensors; neither reads the other.*
Backed by: `sensor_stack.py` on real Falco telemetry (recall emerges, honest misses, blind to `gate.allow`); the belief-frontier red is objective-blind by construction (crown enters belief only via a discovery event); episodic lessons are technique-level only.

**everything-is-liquid** — *Two fixed points; the arms-race null is reported honestly.*
Backed by: Phase-2 null (degenerate episodes excluded, not fabricated); floor held 0.00 every episode.

## ● Partial

**the-ground-moves-too** — *Blue moves the terrain (MTD); the floor re-derives per snapshot.*
Backed by: `live_blue.py` + real credential rotation on the booted range.
Next: the red-vs-blue enterprise duel becomes meaningful once blue is a co-evolving population and red is a credible crown-threat (the mandate build).

## ● Needs compute — mechanism built, experiment not yet run

**crown-reach on real containers** — multi-hop frontier red completes the ≥2-pivot path live without looping. Dry selftest asserts crown-at-depth-2, `oos=0`, chain cold-verified. Next: one paid live episode once the engine is consolidated.
**navigation-adaptation (coarse vs enriched memory)** — `episodic.py` + `episodic_recall`; held until crown-reach is live.
**point-it-at-the-gate (kill-shot, centerpiece)** — diverse red × QD archive + `redteam_gate` (8/8). Next: prove the archive SPREADS, then floor-flat-vs-monitor-curve — now reframed as the two-population co-evolution (Phase 6).
**the-floor-is-a-selection-operator** — `population.py` + QD archive; fixed range, varied scope. (Thesis claim 1.)
**the-average-was-never-the-point** — `stats_tail.py`; unbounded harm metric on live episodes. (Thesis claim informational tail.)

## ● Honest liabilities — named, not hidden

- **`run.py` fabricates both sides** — a dry demo, not evidence. Slated for DELETE in batch-one Phase 1 (it is bound to the cheat-sheet lineage).
- **Auditor drift — CLOSED.** `audit.py` now asserts `EXEC_ACTIONS == reverify_floor.EXEC` in the self-test (a make-test drift guard); the two cold auditors can no longer silently diverge. (Prior entry is resolved.)
- **Gate host-name hardcoding — CLOSED (2026-10-24).** The soft fallback literals are gone:
  `spine.DEFAULT_PORTS` (deleted, zero readers), `audit.DEFAULT_ALIASES` and `reverify_floor.ALIAS`
  (`localhost/127.0.0.1/range-*` deleted). Resolution is topology-driven only (the log's
  `range.topology` ip→name + the general `range-` strip). Verified: the real chains still
  re-derive `oos_executed=0`, and a planted out-of-scope action on a real-topology host is STILL
  flagged after the literals are gone (the literals were never what caught it). (`285986a`)
- **Report layer hardcoded the Struts narrative — module retired.** `report_html.py` was deleted
  in the dead-module cut (`feb7135`); the remaining chain-driven verification is the authority.
- **Confirmation-bias leaks in selection — CLOSED (Phase 6, `3f09c66`).** `manipulation_score`
  reads BLUE's own logged `detect.posture` (not red's `deception.summary`); `score_fitness` +
  `arms_race` read spine-confirmed events (`state.mutate`/`crown.access`), not the dead cascade
  vocabulary. A negative test asserts a red self-report never moves fitness.

## ● Thesis claim scoping — 3/4 realized, not 4/4 (no implied coverage)

Of the four thesis claims, **three have instruments and data; one was cut as unbuilt.** Stated
plainly so the reviewer reads no coverage we don't have:
- **Claim 1 — the floor is a selection operator over an adapting adversary:** BUILT. `gate.py` +
  `reverify_floor`/`audit` (twin cold auditors) + `population.py` MAP-Elites (red AND blue) +
  the two-population co-evolution; the deterministic floor re-derives `oos_executed=0` cold under
  the first full multi-hop crown breach (greedy proof, `77be87b`).
- **Claim 2 — enforce at the boundary the action crosses, not its description:** BUILT.
  `prove_env_boundaries --live` (parser off → `oos_reaches=0`); MSF/weapons fire only via
  `gate.dispatch`; segmentation is the enforcement, `oos_tcp_reaches` measured.
- **Claim 3 — a faithful, re-derivable instrument (no unrecorded effect):** BUILT. hash-chained
  log + `static_coverage` one-effect-path + `live_truth` reconciler (claims vs the targets' own
  telemetry) — the completeness triad.
- **Claim 4 — harm in the SEAMS BETWEEN floors (`multi_floor`):** **CUT as unbuilt.** The module
  was retired (`feb7135`); nothing live backs it. It is framing, not a built claim.
- **Overseer LLM-in-TCB anti-pattern probe:** **CUT as unbuilt** (`overseer.py` retired,
  `feb7135`). Recoverable from git history; not wired into the engine or the suite.

So: 3/4 thesis claims realized with instruments + data, 1 cut. No 4/4 implication anywhere.

## ● Speculation — framing, no build claimed

**what-is-monitoring-for**, **the-joint-attractor**, **the-geography-of-compute** — framings, kept as questions, no build obligation.

## Build timeline — how we got here

**OCT 14–16 · Foundation + vision** — deterministic gate, hash-chained log, Struts range. "Liquid world, two fixed points" set as the target.
**OCT 15 · Two nulls, kept** — lineage-blindspot pilot + co-evolution arms race came back pre-registered nulls, reported honestly.
**OCT 17–19 · Floor proven + strict-live gate** — floor shown two ways; an LLM failure aborts instead of degrading; `verify_live_run.py` the independent gate.
**OCT 20 · Verification-first + real-data turn** — complete-mediation proofs (static coverage, parser fuzzing found three true egress bypasses); committed to a real broad substrate.
**OCT 21 · Native host + Metasploit through the gate** — gated MSF executor; first live foothold (Apache CVE-2021-41773, `fidelity=real`, floor `oos=0`).
**OCT 22 · Enterprise move-space + the navigation gap** — 19-host enterprise range; honest finding that a flat single-hop red can't solo the ≥2-pivot crown.
**OCT 22 · Cleanup pass** — ~70 files moved to `attic/`; canonical set + liabilities written down. NOTE (corrected Oct 23): this cleared historical sprawl but did NOT achieve one-of-each; the duplicates and cheat-sheet remained on disk.
**OCT 23 · Full re-audit + target locked + plan + handoff** — line-by-line read of the whole non-attic tree. Corrected the "converged" overstatement. Sharpened the target (future AI-vs-AI warfare; autonomous tool-authoring agents; Sliver C2; MHBench-real range; two co-evolving populations; penetration-is-a-result; readiness-is-source-not-suite). Wrote the thesis doc, the 7-phase build spec, and the batch-one Claude Code handoff. Chose Sliver for C2 after an Incalmo study (arXiv:2501.16466).

## Roadmap (the 7-phase build spec; full detail in `docs/design-log/2026-10-23-build-spec-to-target.md`)

**Batch one — handed to a fresh Claude Code session 2026-10-23 (convergence + floor + C2):**
- Phase 1 — excise the cheat-sheet lineage (`red_agent`, `red_tools`, `run.py`, `eval.py`, orchestrator prompts); port the 4 real weapons out of `red_tools` first.
- Phase 2 — one attacker engine (the autonomous agent; belief/frontier folded in as awareness).
- Phase 2.5 — real Sliver C2 (implant beacons to a real server; the earned channel for everything post-foothold).
- Phase 3 — one defender engine (the autonomous SOC agent, symmetric; counter-offensive first-class).
- Phase 4 — verb axis in the gate + one effect path.
- STOP and report for review (source-level done-checks). Claude Code does NOT start the builds below.

**Batch two — the two genuine builds (after review):**
- Phase 5 — one range, MHBench topology on real vetted-exploit images.
- Phase 3.5 — tool authoring on both sides (down the one effect path).
- Phase 6 — red population + blue population co-evolving; genome `{prompt, memory, authored_tools}`; telemetry-sourced fitness, never self-report.

**Phase 7 — re-arm the instrument cold** (falsification battery bites, floor re-derives cold, one-of-each by import graph, nothing hardcoded, four claims measurable); rebuild `make test` to the canonical set as a smoke only.

**Submission context:** Nebius × NVIDIA deadline Oct 30; Anthropic Fellows reviewers. The reviewer artifact (claim↔code↔power map + reproduce instructions) rides on the consolidated engine.

---

**The standard:** a reviewer should be able to open the repo and watch each claim either run or self-label its own power, re-derived cold from the hash chain. "It just needs compute" is credible only when the build genuinely backs the writing. `make test` green is never the evidence.
