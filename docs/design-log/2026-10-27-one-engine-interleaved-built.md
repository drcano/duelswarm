# Design log — one engine + the interleaved duel, BUILT and dry-verified (2026-10-27)

Executed the FREE scope of `CC-brief-one-engine-interleaved.md` (Increments A + B). Rationale:
`docs/design-log/2026-10-27-one-engine-interleaved-realtime-duel.md`. The paid canonical run
(Increment C) is separate. Instrument untouched (gate/eventlog/spine/audit/reverify_floor).

## Increment A — consolidated to one clean engine
- Blue's D3FEND response + decision machinery is extracted into ONE shared builder,
  `live_blue_agent.build_blue_tools` (gate-mediated tools, reversible-first + blast-bounded
  eviction, belief read LIVE by reference). Both the post-hoc `run_blue_fight` and the interleaved
  driver use it — one blue logic, no parallel detector. `_STOPS_SPREAD` promoted to module scope.
- The unified duel path uses the REAL-telemetry label-free detector only; the `_P_FIRE` Bernoulli
  survives solely as `run_blue_fight`'s honestly-labelled fallback for callers with no telemetry
  (not in the duel path). Red stays map-blind; three telemetry streams feed the reconciler.
- Run-dir hygiene: `full-real-blue/README.txt` now carries the contamination flag (was empty);
  a top-level `docs/runs/2026-10-26-objective-data-theft/README.md` names the authoritative run.
  Superseded runs kept + labelled, not deleted.

## Increment B — the real-time interleaved duel
`live_blue_agent.run_interleaved_duel` REPLACES the sequential `run_red_agent`-then-`run_blue_fight`
in the unified episode. It is deterministic TURN-interleaving (NOT wall-clock threads):
- Each tick: RED takes ONE action (same gate/spine/eventlog) via `run_red_agent`'s `on_turn` hook;
  then BLUE observes the telemetry window SINCE THE LAST TICK (label-free real-telemetry detector),
  updates belief, and MAY contain — landing BEFORE red's next tick. If blue isolates the foothold at
  tick N, red's tick N+1 from it fails (route severed).
- The event order is a clean total order (red tick, blue tick, …) that re-derives cold. No threads.
- A `duel.outcome` event records the race: `achieved`, `prevented`, `first_contain_tick/seq` (the raw
  fact of when blue first contained), and `tick_of_prevention/prevented_by_seq` set ONLY when
  prevention actually held (a no-op/ineffective containment is NOT reported as a prevention).
- Cadence (one blue observe+act per red action) is a PRE-REGISTERED parameter, not tuned. This
  measures prevention under that observe-cadence; it is not a wall-clock latency claim.

## Verified FREE (no tokens)
- Offline selftest (`swarm/live_blue_agent.py`, in `make test`): BOTH outcomes reachable on one
  re-derivable chain — blue PREVENTS the exfil when its containment is effective in time, red STEALS
  when it is not; the difference is containment EFFICACY (real vs no-op contain_fn), NOT a tuned
  threshold. Belief is real-telemetry-only (label-free), asserted. Red move.source and blue.belief
  beats interleave on the one chain.
- Dry interleaved run on the live unified range (`--no-llm`): `duel.outcome` present; the chain is a
  genuinely INTERLEAVED total order (red seq 6 → blue.belief seq 10 → red seq 11 → blue seq 16 → …);
  `reverify_floor` cold `chain_verified=True, oos_executed=0`; §E held; every `blue.belief` is
  `detector=real-telemetry`. (No-op contain in dry → red achieved; prevention is exercised with a real
  contain, proven in the offline selftest.)
- `make test` green. No parallel loop remains in the unified duel path.

## Not done / next
- Increment C (paid canonical interleaved run, seeds 1337+42, 40 ticks, real Nebius) — awaits the go;
  prereg amended + anchored first (cadence + prevention metric pre-registered). Nothing pushed.
- Possible refinements to watch on the live run: blue's triage can be distracted by a newer alert
  (the dry router targets the last alert host), which can delay containment of the foothold; the
  observe-cadence (one blue act per red tick) bounds how fast blue can escalate investigate→evict.
