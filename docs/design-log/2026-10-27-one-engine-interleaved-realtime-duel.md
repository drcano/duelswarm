# Design log — One clean engine + the real-time interleaved duel (2026-10-27)

Decision record. Dante's call: consolidate every increment into ONE clean engine at full
capability, and build the REAL-TIME INTERLEAVED red/blue loop (blue acts during red's campaign and
can race to contain mid-exfil) — then take canonical measurements. Execution spec is in
`CC-brief-one-engine-interleaved.md`.

## Why interleave at all
The current engine runs red to completion, THEN blue. That is forensics, not warfare: on the
data-theft run, red's exfil completed before blue's containment purely because of ordering, and the
result cannot claim blue could stop the theft. A snapshot of AI-vs-AI conflict requires blue to act
WHILE red operates — to detect from accumulating telemetry and contain before red reaches the
objective. That makes PREVENTION measurable, which is the point.

## The load-bearing decision: deterministic turn-interleaving, NOT wall-clock concurrency
The project's #1 rail is re-derivation at source: the hash-chained log must replay to the same
numbers. Two threads racing in wall-clock time would produce a nondeterministic event order — not
cleanly re-derivable, and only characterizable by running many times. That breaks the epistemology.

So the duel is **turn-interleaved and deterministic**: each tick, red takes ONE action (through the
same gate/spine/eventlog), then blue observes the telemetry produced SINCE THE LAST TICK, updates its
belief (label-free), and MAY act this tick — and blue's containment LANDS before red's next action.
If blue isolates red's foothold at tick N, red's tick N+1 from that host fails (the route is gone).
That is a genuine race in the only sense that matters for prevention — can blue's detect→decide→act
loop beat red to the objective — while the event order stays a clean total order the auditors replay
cold. The per-tick telemetry windowing (`docker logs --since`, the fix from the last session) is
exactly what lets blue observe incrementally; interleaving is its natural consumer.

Honest framing for the writeup: this measures prevention UNDER A DEFINED OBSERVE-CADENCE (one blue
observe+act opportunity per red action). The cadence is a pre-registered parameter, not tuned. It is
not a claim that blue can always stop red, nor a wall-clock latency measurement.

## What stays invariant (the instrument is NOT the fight loop)
Interleaving changes ORCHESTRATION (the driver loop in the engine), never the instrument. Red and
blue still dispatch through the same `gate.py`, ground through the same `spine.py`, log to the same
`eventlog.py`, and are audited by the same `audit.py` + `reverify_floor.py`. Those files are not
touched. The floor reading is unchanged and ordering-independent: `oos_executed`, chain verification,
and hard-floor segmentation do not care about tick order. Interleaving changes the SUCCESS/PREVENTION
metric, not the floor.

## No tuning the race
Tick cadence and blue's belief/decision thresholds are pre-registered and fixed. Whatever happens on
a run — red steals (blue too slow) or blue prevents (contained in time) — is the datapoint. Both are
results. We never adjust cadence or thresholds to manufacture a prevention, exactly as we never tune
toward a hold. A run where red wins the race is as valid and as reportable as one where blue does.

## One engine, no parallel universes
The interleaved driver REPLACES the two sequential calls (`run_red_agent` then `run_blue_fight`). Red
and blue become step-able (one action per tick) and a single driver alternates them. The old
sequential path is retired, not left beside the new one. Consolidation also subsumes: the real-telemetry
label-free detector (retire the standalone `_P_FIRE`-only path or make it the sensor-miss model layered
on real detections, never a parallel detector), the objective-driven map-blind red, the real synthetic
crown, and the three-stream telemetry (net.flow + sys.syscall + svc.event) feeding the reconciler — all
on the one path.

## Full-capability blue
Blue exercises its whole D3FEND set when warranted — proactive deception/decoys and the eviction
ladder (auth-cache-invalidate → kill-session → revoke-cred), not just `isolate_host` — and its
containment is REAL where feasible. The db-core containment that logged `fidelity=SIMULATED`
("beacon ceased after response") becomes a real eviction, or stays honestly labeled if a real one
isn't achievable. In the interleaved loop these actions land mid-campaign and actually change red's
options.

## Safety valve (what "no shortcuts" means under a deadline)
Interleaving is surgery on the engine three days before the deadline. The consolidated engine
(Increment A) is an independently complete, shippable deliverable on its own. If the interleaved loop
(Increment B) cannot be made clean and re-derivable in time, we DO NOT ship a half-wired concurrent
hack to claim prevention — we fall back to the consolidated post-hoc engine, labeled honestly, and
land interleaving right afterward. Quality bar over clock.

## Out of scope (unchanged)
- Destructive tooling (DoS/ransomware/wipe) — still deferred; threatens the instrument; no baseline.
- Wall-clock concurrency — deliberately NOT built (breaks re-derivability, as above).
- Dwell objective — optional later; the interleaved loop makes it a real contest when we add it.

## Verification (what the verifier re-derives cold)
- The interleaved chain is a valid total order; hash chain intact; `reverify_floor` cold:
  `chain_verified=True`, `oos_executed` as-is, hard floor held.
- Blue's actions are telemetry-sourced and label-free; map-blind assertion for red still passes.
- Both outcomes (theft and prevention) are reachable and recorded honestly; the `duel.outcome`
  event states objective achieved/prevented, the tick of each, and the blue action that prevented.
- No parallel loop remains (one driver); the retired sequential path is gone/quarantined.
- All three telemetry streams present; run-dir hygiene fixed (authoritative run labeled, contaminated
  run flagged).
