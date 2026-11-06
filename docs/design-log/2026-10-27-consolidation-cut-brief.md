# CC execution brief — the consolidation cut to ONE clean engine (2026-10-27)

Approved from the cut map (`docs/design-log/2026-10-27-cut-map.md`), with the build CC's three
source-grounded corrections folded in and all six forks decided by Dante. This supersedes the cut-related
parts of `2026-10-27-wire-red-arsenal-into-one-engine.md` (the frontier-driver absorb + proof fold happen
HERE, once); the arsenal→live-path *capability* wiring in that brief is the follow-on after this
structural cut lands.

Sequenced so every free, verifiable step precedes the destructive one. **The ~35-file destructive pass
is STEP 4 and waits for Dante's explicit go even though the map is approved.** Nothing pushed.

## Rails (unchanged)
NO NEW MODULES — move/extract capability into the one engine, never re-implement beside it. ONE attacker,
ONE defender, ONE range, ONE duel loop. INSTRUMENT FROZEN: `gate`/`eventlog`/`spine`/`audit`/`polymorph`/
`uninstrumented` + `reverify_floor` + `scripts/mediation/{static_coverage,parser_fuzz,reachability_probe}`.
Red MAP-BLIND, blue LABEL-FREE, Nebius-only counted, author `Dante Cano <drcano@ucsd.edu>`. `make test` is
a smoke check, rebuilt to match the cut — never kept green for its own sake, never the done-signal. No
tuning; `oos_executed` is measured, not targeted. Nothing pushed; destructive step gated.

## The six decisions (locked)
1. **sensor_stack vs sensor_real — CONDITIONAL.** Rewire `prove_sliver_c2` to `sensor_real`
   (`detected_techniques(telemetry, threshold=1)`, sensor_real.py:135) and run its selftest. **If the
   Sliver-beacon `"T1071" in dets` assertion still holds → DELETE `sensor_stack.py`. If T1071 drops →
   KEEP `sensor_stack` (it carries a C2 detector the thesis needs) and report that finding.**
2. **deception.py — DELETE** (git-recoverable). Sole importer is `prove_deception` (also deleted);
   claim-4/seams is cut; nothing on the one engine touches it.
3. **Co-evo harness (`instrument.py`, `instrument_live.py`, `env_coevo.py`, `live_gates.py`) — KEEP until
   Phase 6.** Confirmed the only co-evolution scaffold; deleting now removes it before its one-engine
   replacement exists. A conscious "later," not a silent keep. Do NOT touch these in this pass.
4. **run_discovery_duel — KEEP (inside `live_red`); delete only `scrutiny_duel.py`.** Confirmed a
   dry/verify helper used by `verify_live_run` (KEEP) + `instrument_live` (kept per #3);
   `run_interleaved_duel` stays the sole MEASUREMENT duel.
5. **wall.py — FOLD into the engine selftest, PRESERVE the fixture.** `make test` (Makefile:65-66) has
   `reverify_floor` cold-read `data/wall/range_0.jsonl`; the fold MUST keep producing that range fixture
   so the independent cold re-derivation keeps its input. Then delete `wall.py` itself.
6. **viz/ + judge.py — DELETE (Dante).** Rebuild a visualizer after the complete build. This requires
   stripping the optional `--viz` hook from the one engine: the `--viz` arg
   (`live_arms_race_run.py:772-773`), the `if a.viz:` block (781-786), and the `_viz_push` global + its
   per-event call sites; plus the Makefile `viz`/`viz-dry`/`viz-replay` targets. Then delete `viz/`
   (`server.py`, `index.html`, `events.jsonl`) and `swarm/judge.py` (its only importer was `viz/server.py`).

## STEP 1 — absorb + fold (free; no deletions yet)
1. **Absorb the shared driver** `dry_multihop_episode` / `run_live` out of
   `scripts/arms_race_enterprise_frontier.py` into the ONE engine (`swarm/live_agent.py` +
   `swarm/live_red.py`), LIVE via the Nebius router / DRY via `DryOODARouter` — one code path, two routers.
2. **Fold the milestone invariants into ONE engine selftest** (extend `swarm/live_agent.py`'s selftest or
   a single `scripts/prove_engine.py` — no net-new module beyond at most this one consolidated selftest,
   justified): zoned multi-hop-to-crown-at-depth-2 (d2), multiservice foothold (d3), autonomy +
   discovery-driven + reconciler-wired (d4), spine law + coordinates + segmentation (spine),
   earned-channel loot reuse (phase2_loot), blue eviction (live_eviction), MSF-only-via-gate (msf_floor),
   tier routing (tiering), authoring-on-the-one-effect-path (tool_authoring), and the gate-invariant-
   across-N-ranges that produces `data/wall/range_0.jsonl` (wall). No invariant dropped.
3. **Re-point** `verify_live_run`, `instrument_live` (kept) and any kept apparatus off the frontier file
   onto the one engine. Report: the folded selftest green, `reverify_floor` cold on the fixture, and the
   CURRENT `make test` still green at this point (nothing deleted yet).

## STEP 2 — the D1 gate (free)
Rewire `prove_sliver_c2` → `sensor_real`, run its selftest, record whether T1071 still asserts. This
decides sensor_stack's fate before the destructive pass. Report the result.

## STEP 3a — re-point the two instruments onto the one engine (free; REVIEWED, before any deletion)
These edits MUST land and verify green **before** STEP 4 deletes the files they reference — otherwise a
check runs over deleted entries and passes **vacuously** (a silent weakening). Both are verified at
source, with the diff + output reported to Dante; no oracle logic changes, only the entrypoints each is
asserted over.

- **`scripts/mediation/static_coverage.py` (FROZEN — Dante-approved reviewed change, 2026-10-27).**
  Its `COUNTED_ENTRIES` (lines 42–48) are all three on the delete list (`prove_n2n3_tiered`,
  `exp_a_control_eval`, `arms_race_enterprise_frontier`), and its `isolation()` only walks entries that
  exist — so deleting them leaves the class-2 isolation check **vacuously ISOLATED**. Re-point
  `COUNTED_ENTRIES` to the **agent closures that must stay blind to the gate-off channel**:
  `swarm/live_agent.py`, `swarm/live_red.py`, `swarm/live_blue_agent.py`. Do NOT point it at
  `scripts/live_arms_race_run.py`: the harness deliberately imports the class-2 `uninstrumented` channel
  for the §E hard-floor probe (`live_arms_race_run.py:561`), which is sanctioned harness MEASUREMENT
  (class-4), not an agent move — folding it into the counted set would be a false LEAK. (This mirrors
  `leak_test`'s own agent-scoped `RED_ENTRYPOINTS`, so the two instruments agree.) Also drop the stale
  `SCAN_FILES = ["run.py"]` (run.py is deleted). **Nothing else in the oracle changes.** VERIFY and report:
  `isolation()` runs NON-VACUOUSLY (closure_size > 0 for each of the three agent entries), every one
  reports ISOLATED, and `static_coverage` PASSes honestly — not green because the walk was empty.
- **`scripts/validation/leak_test.py`.** Drop `scripts/arms_race_enterprise_frontier.py` from
  `RED_ENTRYPOINTS` (lines 24–28); keep `swarm/live_agent.py`, `swarm/live_red.py`. Its positive control
  (plants a fake leak, asserts it is caught) still fires and the closure stays ≥3, so it cannot go
  vacuous. Report the selftest green (LEAK-FREE + positive control caught).

## STEP 3b — rebuild `make test` to the canonical smoke set (free)
Remove every invocation of a to-be-deleted file (`arms_race_enterprise_frontier --selftest`, `prove_d2/
d3/d4 --selftest`, `prove_spine`, `wall --selftest`, `prove_phase2_loot_reuse`, `prove_tiering`,
`prove_tool_authoring`, and — per D1 — `prove_sliver_c2`/sensor_stack as resolved). Point the cold
`reverify_floor` read at the fixture now produced by the folded engine selftest. Keep: `gate`,
`live_agent`, `live_blue_agent`, `coevolve`, `benign_baseline`, `prove_stealth_*`, `prove_one_engine`,
`prove_env_boundaries`, `redteam_gate`, `prove_falsification`, `static_coverage`, `scripts/validation/*`,
`topo_to_compose --unified`, `live_postex`, `live_pivot`, `preregister --verify`, the folded engine
selftest, and the cold reverify. `make test` green on the NEW set. (This rebuild is load-bearing: `make
test` today still invokes the engine we're deleting.)

## STEP 4 — the destructive pass (LAST; Dante's explicit go required)
Delete only after Steps 1, 2, 3a, 3b are green and reported — in particular, `static_coverage` and
`leak_test` must already be re-pointed and NON-VACUOUSLY passing, so deleting their old entrypoints
cannot hollow a check. Extend `prove_one_engine` to assert ONE red / ONE
blue / ONE range / ONE duel loop and that every deleted engine is gone, by import graph.

**Delete (parallel engines / drivers / legacy):** `scripts/arms_race_enterprise_frontier.py`,
`arms_race_enterprise.py`, `arms_race_check.py`, `measured_duel.py`, `scrutiny_duel.py`,
`run_decision_experiment.py`, `run_experiments.py`, `prove_n2n3_tiered.py`, `prove_n3_live_blue.py`.
**Delete (folded or obsolete milestone proofs — subsumption-verified 2026-10-27):**
`prove_d2_zoned_traversal.py`, `prove_d3_multiservice_foothold.py`, `prove_d4_autonomous_agent.py`,
`prove_spine.py`, `prove_phase2_loot_reuse.py`, `prove_live_eviction.py`, `prove_msf_floor.py`,
`prove_tiering.py`, `prove_tool_authoring.py`, `wall.py`; `prove_brick1.py` (subsumed by
`swarm/live_red.py`'s §2 selftest — **delete only after `swarm/live_red.py` is added to the smoke set**,
else its coverage goes with it); `prove_checkpoint1.py` (obsolete — validates the orienteering/decision-
experiment rig, which is all deleted). **NOT deleted (subsumption check found them non-subsumed):
`prove_corpus_floor.py` and `prove_e2e_broad.py` — see KEEP below.**
**Delete (dead swarm modules — 0 live importers):** `swarm/blue_llm.py`, `blue_counter_recon.py`,
`report.py`, `live_blue.py`, `orienteering.py`, and `judge.py` (D6).
**Delete (D2 / D6 / peripherals):** `swarm/deception.py`, `scripts/prove_deception.py`; `viz/` +
the engine's `--viz` hook + Makefile viz targets; `scripts/analyze_lineage.py`, `kill_shot_chart.py`,
`power_analysis.py`, `power_v4.py`, `verify_report.py`, `exp_a_control_eval.py`.
**Delete per D1 result:** `swarm/sensor_stack.py` + `scripts/prove_e2e_broad.py` only if T1071 still
asserts on `sensor_real`.

**Keep / consolidate-later (do NOT delete):** the instrument; the one-engine closure; the independent
apparatus; the co-evo cluster + its harness (#3); `beacon.py` + `prove_sliver_c2` (Sliver, Phase 2.5);
`prove_control_reasoning` (H1); `prove_stealth_*`; `stats_tail` (deferred); `run_discovery_duel` (#4);
`prove_corpus_floor` (floor re-derivation over the whole committed corpus — reproducibility apparatus in
the `reverify_floor` family, a check that bites, not a milestone); `prove_e2e_broad` (the integrated
kill-chain lap + multi-sensor blue; imports the kept `sensor_stack`; exercises MSF foothold→lateral→exfil
the one engine can't yet fold in — **revisit after the arsenal→live-path wiring, do not fold now**).

## Verify after STEP 4 (the done-check, re-derived cold)
`reverify_floor` cold `chain_verified=True, oos_executed=0` on a fresh run; `static_coverage` (no
ungoverned sink); `prove_falsification` + `redteam_gate` still bite; `prove_env_boundaries` §E; extended
`prove_one_engine` shows one-of-each and the deleted engines gone; `make test` green on the rebuilt set.
Commit on `real-range` per phase with the source-level done-check; nothing pushed.

## Reporting
Report after STEP 1 (absorb+fold green), STEP 2 (D1 / T1071 result), STEP 3a (the two instrument diffs +
non-vacuous ISOLATED / LEAK-FREE output), STEP 3b (make test rebuilt green), then HOLD for Dante's go on
STEP 4; after STEP 4, the cold done-check above. Then the arsenal→live-path capability
wiring (the other brief) rides on the consolidated engine.
