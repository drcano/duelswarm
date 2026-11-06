# Design log — Increment 2: a real-telemetry, label-free blue detector (2026-10-27)

Landed the Increment-2 defender per the brief: blue's belief now derives from a REAL detector over
the REAL captured telemetry, not the hardcoded per-stage Bernoulli. Instrument untouched
(gate/eventlog/spine/audit/reverify_floor); floor reading unchanged. Prereg amended + re-anchored
(seq 25, `docs/prereg/INCREMENT_2_REAL_DETECTOR.md` + `swarm/sensor_real.py` registered) BEFORE the
verification run.

## What changed
- `swarm.sensor_real.telemetry_detections(service_logs)`: the label-free detector that feeds belief.
  It matches Sigma-style SIGNATURES against the targets' own service logs (sshd `-e` auth, the Struts
  Jakarta-Multipart fault, the Apache path-traversal tell) and emits one detection per (host,
  technique), each carrying the matched LOG LINE (`source_line`) and a per-signature reliability prior
  (its precision), never a per-stage probability over red's actions. SIGMA_RULES gained a stage +
  reliability; the detect/score paths and `live_telemetry.parse_service_events` updated to the wider tuple.
- `swarm.sensor_real.assert_label_free(...)`: air-gap guard — raises unless every detection traces to a
  real telemetry line with a `real-telemetry[...]` basis. Run at detection time in the unified episode
  and guarded in `make test` with a positive control (a fabricated, non-telemetry detection is caught).
- `swarm.live_blue_agent.run_blue_fight(telemetry_fired=...)`: when real detections are supplied, belief
  is the noisy-OR over them (+ blue's own honeytoken tripwires); otherwise it falls back to the MODELED
  Bernoulli and records `blue.detector="modeled"` — the no-shortcuts clause (never a fake-real detector).
  A `blue.detector` record states which ran. The `blue.detect.bernoulli` event NAME is kept (a legacy
  schema key the L1 gate reads); its `basis`/`source_line` fields carry the honest provenance.
- `scripts/live_arms_race_run.py` unified episode: SENSE before deciding — capture the service logs,
  build `telemetry_fired = sensor_real.telemetry_detections(...)`, pass it to `run_blue_fight`; the
  reconciler reuses the same capture so blue and the reconciler see one record.

## An honesty bug caught in verification (and fixed)
First dry verification showed blue detecting the foothold (dmz-web Struts fault) and the FAILED pivot
to wks-01, but NOT the successful db-core login. Root cause: the db-core standup sshd RESTART (added
in Increment 1 to apply the plaintext-cred password) ran `/usr/sbin/sshd -e 2>/dev/null &` — the
`2>/dev/null` silenced sshd's `-e` auth output, so `Accepted password` never reached `docker logs`.
That is a MEASUREMENT ARTIFACT (an artificial blind spot on the crown host), not a real sensor limit —
it would have understated blue and overstated red's stealth. Fixed to `/usr/sbin/sshd -D -e &` (no
redirect, mirroring the base loot command) so auth events reach the telemetry. The detector's rule was
already correct; only the telemetry was being dropped.

## Verified (FREE dry run, no tokens; evidence persisted)
`docs/runs/2026-10-26-objective-data-theft/increment2-detector-verify/`: `blue.detector=real-telemetry`;
THREE detections, each traced to a real log line —
- T1190 dmz-web: the real `org.apache.struts2.dispatcher.multipart...` fault (the S2-045 foothold),
- T1021 db-core: the real `Accepted password for dbadmin from 10.40.0.11` (the crown-host login),
- T1110 wks-01: the real `Failed password for invalid user dbadmin from 10.20.0.10` (red's rejected pivot).
Belief p_compromise=0.985 derives from these (noisy-OR), detector=real-telemetry; air-gap guard passed;
the crown chain still completes (exfil bytes_len=2537, matches_expected=True); floor cold
chain_verified=True oos_executed=0. Recall is MEASURED/lossy by construction (exfil over an
already-established session leaves no new auth line — undetectable from auth telemetry).

## Reading it straight / next
Blue is now a real defender: its belief is what the sensors actually saw, label-free and traceable, not
a model. `make test` green. This was verified FREE — the detector behaves identically under an LLM-driven
duel (it reads telemetry, not red's planner), so no tokens were spent to land it. A PAID data-theft run
WITH the real detector would measure the real blue-vs-red contest (did blue's real-telemetry belief
clear the contain gate and evict before red completed exfil) — a separate, optional measurement. Nothing
pushed; committed on `real-range`.
