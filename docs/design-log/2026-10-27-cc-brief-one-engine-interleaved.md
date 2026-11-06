# CC brief — one clean engine + the real-time interleaved duel (2026-10-27)

Execute autonomously, report each stage, stop on a real problem. Rationale in
`docs/design-log/2026-10-27-one-engine-interleaved-realtime-duel.md` — read it first. Posting this
brief is Dante's go for the FREE build + verification only. The canonical PAID run at the end waits
for a separate explicit go.

## Rails (load-bearing — hold them, do not relax for the deadline)
- NO TUNING toward any outcome. Red steals or blue prevents — both are results. The cadence and
  blue's thresholds are pre-registered and fixed; never adjust them to manufacture prevention. The
  ONLY failure is an unrecorded effect.
- ONE clean engine. The interleaved driver REPLACES the sequential path; retire the old one, no
  parallel universes, no second detector.
- The INSTRUMENT is not modified: `swarm/gate.py`, `swarm/eventlog.py`, `swarm/spine.py`,
  `swarm/audit.py`, `redteam/reverify_floor.py`. Interleaving changes ORCHESTRATION only. If you think
  you must change the instrument, STOP and report.
- Two floors never conflated. The floor reading is ordering-independent and must re-derive cold.
- Red stays MAP-BLIND (intent-aware, ground-truth-blind); `assert_red_map_blind` keeps passing.
- Blue stays LABEL-FREE: detects only from real telemetry + its own traps, never red's labels or gt.
- All counted model calls through Nebius Token Factory. Commit author `Dante Cano <drcano@ucsd.edu>`.
- Nothing pushed / nothing off `real-range` without explicit go. Ask before ANY paid spend.
- Readiness = RE-DERIVATION AT SOURCE. `make test` green is a smoke check, never the done-signal.
- Persist every chain under `docs/runs/…` with all three streams, for cold re-derivation.

## North star
One engine: objective-driven map-blind red vs. real-telemetry label-free blue, interleaved in real
time so blue can contain mid-campaign, on the unified range with a real synthetic crown, all three
telemetry streams, floor re-derivable cold. Build and verify FREE first; measure after.

---

## INCREMENT A — Consolidate to one clean engine (FREE)
Wire the increments already built into a single path and retire the rest.
- One path carries: objective-driven map-blind red (`data_theft` wired; mechanism generic; destructive
  NOT defined), the real synthetic crown dataset, the real-telemetry LABEL-FREE blue detector, and all
  three telemetry streams (`net.flow` from Falco connects + conntrack, `sys.syscall`, `svc.event`)
  feeding the reconciler on EVERY run.
- Retire/quarantine superseded code: the standalone `_P_FIRE`-only Bernoulli detector becomes, at most,
  a sensor-miss model LAYERED on real-telemetry detections — never a parallel detector. No dead paths.
- Blue at full capability: exercise the whole D3FEND set when warranted — proactive deception/decoys
  and the eviction ladder (auth-cache-invalidate → kill-session → revoke-cred) — not just
  `isolate_host`. Make containment REAL where feasible; the db-core `fidelity=SIMULATED` eviction
  becomes a real one, or stays HONESTLY labeled if a real one isn't achievable.
- Run-dir hygiene: write a real flag into the empty `full-real-blue/README.txt` marking it contaminated
  (cumulative-logs), and add a top-level README in `docs/runs/2026-10-26-objective-data-theft/` naming
  the authoritative run. Do not delete superseded runs; label them.
- Honest fidelity labels throughout. `make test` green. Instrument untouched.
- FREE dry verification that the consolidated engine runs end-to-end (no tokens).
- Increment A is an independently complete, shippable engine. If Increment B can't be made clean in
  time, we ship A, labeled honestly, and defer interleaving. Do NOT ship a half-wired loop.

## INCREMENT B — The real-time interleaved duel (FREE build + verify)
Replace the sequential `run_red_agent`-then-`run_blue_fight` with ONE deterministic turn-interleaved
driver.

### Architecture (deterministic turn-interleaving, NOT wall-clock threads)
- Make red and blue STEP-ABLE: red takes ONE action per tick (not run-to-completion); blue gets ONE
  observe+decide+maybe-act per tick. A single driver alternates them.
- Per tick:
  1. RED: one action through the SAME `gate.dispatch` → `run_effect` → `spine.confirm` →
     `state.mutate`, logged to the one chain. Map-blind, objective-driven.
  2. TELEMETRY: capture the window SINCE THE LAST TICK (`--since`), emit `net.flow`/`sys.syscall`/
     `svc.event`.
  3. BLUE: observe that window, update belief (label-free, real-telemetry detector), and if belief
     clears the pre-registered threshold, ACT this tick (contain/evict/decoy) through the same
     gate/spine. Blue's action LANDS before red's next tick — if blue isolates red's foothold at tick
     N, red's tick N+1 from it fails (route gone).
- STOP when: red achieves its objective, red has no viable move, or max_turns.
- Determinism: the EVENT ORDER is a clean total order (red tick, blue tick, …); the chain re-derives
  cold. Do not introduce threads/async that make the order nondeterministic.

### New measurement (does not touch the floor)
- Emit a `duel.outcome` summary event (re-derivable from the chain): `{objective, achieved: bool,
  prevented: bool, prevented_by_seq, tick_of_objective, tick_of_prevention}`. This records the race
  result as a first-class fact.
- The FLOOR reading is unchanged and ordering-independent (`oos_executed`, chain verify, hard floor).
  Interleaving changes the PREVENTION metric, not the floor.

### Guardrails
- Cadence (one blue observe+act per red action) and blue thresholds are PRE-REGISTERED and fixed. No
  tuning toward prevention or theft.
- One driver only; the sequential path is retired.
- Instrument untouched; blue label-free; red map-blind — all still asserted.

### FREE verification (no tokens) — make these true, don't assert them
- A dry interleaved run re-derives cold: `reverify_floor` `chain_verified=True`, `oos_executed=0` (or
  as-is), hard floor held; the chain is a valid total order.
- Demonstrate BOTH outcomes are reachable in dry: one config where blue contains before red exfils
  (prevention) and one where red completes first (theft) — proving the race is real and not rigged,
  and `duel.outcome` records each honestly.
- Blue actions trace to real telemetry, label-free; `assert_red_map_blind` passes; all three streams
  present; no parallel loop remains.

## INCREMENT C — Canonical measured run (PAID — WAITS FOR SEPARATE GO)
Do NOT spend until Dante gives a fresh go after A+B verify clean.
- Pre-flight (free, zero credits): the consolidated interleaved engine stands up on the unified range,
  map-blind passes, the crown dataset is real, the three streams capture, the floor re-derives cold on
  a dry run. If any wiring is wrong, STOP and report (the Part-B pattern). Do not bolt on and spend.
- Then, on the GO: seeds 1337 + 42, 40 ticks, real Nebius red+blue interleaved. ONE run per the
  framing Dante locked: whatever red/blue do on these two seeds is the datapoint — NO re-rolling for a
  theft or a prevention outcome. Report the measured result (objective achieved/prevented per seed as
  its own metric; floor as a separate cold-re-derived reading), token spend, all three streams
  persisted under `docs/runs/2026-10-27-interleaved-canonical/`.

## Prereg (amend + anchor before the paid Increment-C run)
- The duel is deterministic turn-interleaved; define the observe-cadence as a pre-registered parameter
  (one blue observe+act per red action) and state it is not tuned.
- The PREVENTION metric (`duel.outcome`): objective achieved vs prevented, and the tick of each.
- The floor reading remains objective- and ordering-independent; both theft and prevention are results.
- Blue thresholds fixed and pre-registered; no tuning toward either outcome.

## Out of scope (explicit)
- Destructive tooling (DoS/ransomware/wipe/shutdown) — deferred; threatens the instrument; no baseline.
  Keep the objective mechanism generic to accept it LATER behind guardrails; wire ZERO now.
- Wall-clock concurrency — deliberately not built (breaks re-derivability).
- Dwell + domain-dominance objectives — later.

## Reporting
Report after: Increment A (consolidated engine, dry-verified, hygiene fixed); Increment B (interleaved
driver, both outcomes demonstrated dry, cold re-derivation); the Increment-C pre-flight (stop-or-go);
and — only after the go — the canonical run. Nothing pushed. Persist all chains with three streams.
