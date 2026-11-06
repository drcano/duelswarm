# CC brief — the arsenal onto the ONE measurement engine (2026-10-27)

Grounded on the POST-CUT tree (8715a91), read at source. This supersedes the earlier
`wire-red-arsenal` brief, which was written before the absorb — the picture is now different and better.

## The finding (verified at source)
After the consolidation, `swarm/live_red.py` holds **two red driver families**, and the arsenal is in
the wrong one for measurement:
- **(A) the interleaved MEASUREMENT engine.** `build_agent_tools` (L296) → driven by
  `live_agent.run_red_agent` → `run_interleaved_duel`. Toolset `{scan,fingerprint,exploit,harvest,pivot,
  loot}`. Its `fingerprint` is the **STUB** (L407 `"observed at recon time"`) and `exploit`/`pivot` are
  `live_pivot.cred_pivot` only (L368/386). **No arsenal.** This is the engine `prove_one_engine` certifies
  as the sole measurement duel — i.e. the engine we report on has a weak red.
- **(B) the frontier/multihop family.** `live_frontier_executors` (L1001) → FrontierService →
  `run_live` / `dry_multihop_episode`. This has the **real arsenal**: `live_fingerprint.fingerprint_service`
  (real recon), `live_vector.make_llm_vector_planner` (red infers the CVE from its own fingerprint),
  `live_weapon.fire_vector` (entry: MSF catalog or response-weapon), `live_lateral.lateral_exploit` (inner
  hops through earned shells), byte-grounded exfil, honest `foothold_failed`/`lateral_failed`, gate-mediated
  throughout (the free-pick OOS probe is realized as a real lateral so the gate denies it — the floor test,
  live). This family drives `prove_engine`'s d2/d3/d4 folds and the D2/D4 paid legs — **not** the
  interleaved measurement duel.

The exploit PRIMITIVES (`fingerprint_service`/vector planner/`fire_vector`/`lateral_exploit`) are already
single-source. What is NOT shared is the ORCHESTRATION — the observe→infer→fire→lateral→exfil sequencing
and its state (`shells`, `observed_fp`, `msf_sessions`) — which lives only in `live_frontier_executors`.
`build_agent_tools` (the measurement engine's toolset) has none of it.

## The decision
`run_red_agent` is already the ONE interleaved driver and it is **tool-agnostic** (L447: it fires whatever
`{name: callable→result}` dict it is handed, reading `grounded/owned/looted/blocked`). So the arsenal does
not need a new driver or a new loop — it needs to be the toolset `run_red_agent` is handed on the
measurement engine. The rule from CLAUDE.md governs how: **move/extract the capability, never
re-implement it beside the old copy.** So:

1. **Extract the arsenal orchestration out of `live_frontier_executors` into ONE shared helper** (a stateful
   builder in `swarm/live_red.py` — no new module unless unavoidable): holds `shells`/`observed_fp`/
   `msf_sessions`; exposes the steps `observe`→`fingerprint`(`fingerprint_service`)→`infer`(the vector
   planner)→`fire`(entry: `fire_vector`; inner: `lateral_exploit`)→`exfil` (byte-grounded). It calls the
   existing single-source primitives; it does not reimplement them.
2. **Rewrite `build_agent_tools` to back its `{scan,fingerprint,exploit,harvest,pivot,loot}` tools with that
   shared helper** — `fingerprint`→`fingerprint_service`, `exploit`→(entry `fire_vector` via the inferred
   CVE / inner `lateral_exploit`), `pivot`→`lateral_exploit`, `loot`→byte-grounded exfil, keeping the schema
   `run_red_agent` and `RED_AGENT_SYS` already speak and the `{grounded,host,owned,looted,blocked}` result
   contract `run_red_agent` reads. This retires the stub fingerprint and the cred-pivot-only exploit on the
   measurement path. Keep `cred_pivot` available as a modality the planner can fall through to (both are
   real tradecraft), not as the only one.
3. **Refactor `live_frontier_executors` to call the same shared helper**, so the arsenal orchestration
   exists in exactly one place and both the interleaved measurement engine (A) and the frontier proof
   driver (B) fire the identical arsenal — zero duplicated orchestration.

## The one design detail to resolve at source BEFORE the big rewrite (report first)
`live_frontier_executors` is bound to the frontier `chain` model (an enterprise attack-graph structure);
`build_agent_tools` is bound to the unified range's coords (`foothold_container`, `entry_net`, discovered
inner subnets). The shared helper must serve both without one being handed the other's map. Read both
range models and report how the shared helper takes its structure (e.g. a thin adapter from each range to
the helper's needs) BEFORE rewriting — do not force a `chain` onto the unified range or vice versa.

## Rails (unchanged — a violation invalidates it)
- Red stays MAP-BLIND: the planner sees only the fingerprints red observed (`live_vector` self-tests the
  no-leak invariant — keep it); `assert_red_map_blind` still passes.
- The floor is TESTED, not protected: the arsenal's OOS pivot stays realized as a real gate-mediated
  lateral so the gate denies it and `oos_executed` is the measured outcome, reported as-is (a breach is a
  result). `reverify_floor` re-derives cold.
- Blue LABEL-FREE; §E hard-floor probe untouched; Nebius-only counted; matched-tier: pin the planner role
  to `red.orchestrator` (ultra) on the matched-tier seat so no second tier sneaks in.
- INSTRUMENT FROZEN (`gate`/`eventlog`/`spine`/`audit`/`reverify_floor`/`static_coverage`). NO new module
  unless unavoidable (justify). Nothing pushed; paid runs wait for an explicit go. No tuning.

## Sequencing (free + verifiable first)
1. Report the range-model reconciliation plan (the detail above). HOLD for Dante.
2. Extract the shared orchestration + rewrite `build_agent_tools` + refactor `live_frontier_executors`.
3. **Dry-verify on the interleaved dry path** (`DryOODARouter`, no tokens/Docker API): the measurement
   engine now emits real `fingerprint_service` dicts, `move.source:llm` vector beats, grounded
   `fire_vector`/`lateral_exploit`, at least one honest `foothold_failed`/`lateral_failed`; `reverify_floor`
   cold `chain_verified=True`; `prove_engine --selftest` + `static_coverage` + `make test` green; one red
   driver still (`prove_one_engine`).
4. Report; HOLD for the paid matched-tier run.

## Follow-on (flagged, NOT this pass)
Fully retiring the frontier driver so `run_red_agent` is the SOLE red driver (re-pointing the d2/d3/d4
proofs + the D-legs onto the interleaved engine) is the true one-red-driver endgame. After this pass both
drivers share one arsenal orchestration, so there is no capability duplication — the remaining difference
is loop structure (interleaved OODA vs frontier-move multihop), and the measurement engine uses the
interleaved one. Converge the drivers next, once the arsenal is proven on the measurement engine.

## Reporting
After step 1 (reconciliation plan — HOLD), step 3 (the rewrite + dry-verify logs), then HOLD for paid.
Nothing pushed.
