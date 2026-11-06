# Group A verification — cold, zero spend
**Date:** 2026-10-30
**Branch:** real-range
**Scope:** 2026-10-30 co-evolution selection + erosion build brief, Group A units A-D1, A-S1, A-S2, A-S3

## What verified cold

### 1. Floor still re-derives to oos_executed=0 on every committed pilot chain
```
FLOOR  gen0_4a62d3b42d40.jsonl  chain_verified=True  oos_executed=0
FLOOR  gen0_5a4b032e134d.jsonl  chain_verified=True  oos_executed=0
FLOOR  gen0_de6f0c20cc73.jsonl  chain_verified=True  oos_executed=0
```
No TCB file touched by this build (gate.py, eventlog.py, spine.py, audit.py,
redteam/reverify_floor.py, scripts/mediation/static_coverage.py). The pilot
run directory stays untouched as a regression fixture, per the brief.

### 2. A-D1 unified detection predicate counts match duel.outcome ground truth
```
A-D1   gen0_4a62d3b42d40.jsonl  predicate=21  truth=21   (previously 0)
A-D1   gen0_5a4b032e134d.jsonl  predicate=19  truth=19   (previously 0)
A-D1   gen0_de6f0c20cc73.jsonl  predicate=22  truth=22   (previously 0)
```
Pre-A-D1 each site used `str(action).startswith("detect")`, which matched
nothing on the live vocabulary (a real detection is `blue.detect.bernoulli`,
one per fire; `blue.detector` is a per-tick observer rollup whose
`detections` field is a cumulative count, 1→3→5→…→21 across ~39 ticks).

**Deviation from the brief's literal, with justification:** the brief said
"count `blue.detect.*` and `blue.detector`" but ALSO required "Confirm the
exact live names against a committed chain before settling the predicate."
Counting `blue.detector` as a per-fire event would 3×-over-count (and summing
its `detections` field ~30×). The confirmed-against-the-chain predicate is:

```
actor == "blue"  AND  (action.startswith("blue.detect.")
                       OR action == "detect.eventlog")       # legacy stub
                 AND  action NOT in {detect.posture, blue.detector,
                                      blue.detector_in_use, blue.belief,
                                      blue.would_contain}    # attention/posture
```

### 3. A-S1/A-S2 — selection fires on corroborated wins through Evolver.tick
```
Evolver.tick(three pilot chains):
  pop_size=3  scored=2  degenerate=1  excluded=0  archive_entries=1  best_fitness=0.72
```
Pre-A-S1/A-S2: scored=0 of 3 (archive_entries=0, best_fitness=0, red_cells=0).
Post: both corroborated wins (gated_objective==1.0) pass the degeneracy gate
and raise best_fitness; the uncorroborated chain stays degenerate-excluded.
Two wins collapse into one archive cell by MAP-Elites design (identical
behavior descriptors) — this is scoring correctness, not an archive bug.

### 4. A-S3 — spine-exfil terminator is defense in depth
`run_red_agent` selftest green: a scripted path where the loot tool emits
`state.mutate(state=exfil)` but does NOT surface `looted` in the result
still terminates with outcome=`objective_claimed`; the post-exfil tail is
at most one turn.

### 5. Unit-L loop-logic selftest green (no Docker, no tokens)
`scripts.live_arms_race_run._live_loop_selftest()` passes:
  * red_live selection on the gated verdict (witnessed gen scores + enters archive)
  * all-falco-down gen EXCLUDED and surfaced as DEGRADED (never a silent zero-fitness gen)
  * floor oos=0 cold on every per-gen chain; two auditors agree
  * memory-channel map-blind guard bites on a GT-name lesson

## Not yet run (needs Dante's go)
A booted-range FREE dry generation (`use_llm=False` through
`run_live_generations` on live Docker). The Docker-free Unit-L loop-logic
selftest exercises the same `run_live_generations` function on a stub
episode (same selection / exclusion / per-gen-hooks / all-excluded guard /
map-blind guard code path) and is cold green; the booted-range dry gen
would additionally exercise the live tool stack with a deterministic
router and no tokens. Available on request.

## Commits in this verification window
```
d862ac1  A-D1: unify blue-detection predicate across the five sites
6ee6220  A-S1 + A-S2: score every corroborated win; degeneracy on compromise-state
5dcacba  A-S3: terminate on the spine-confirmed objective (defense in depth)
```

## Reproduction
```bash
# Floor + A-D1 + A-S1 re-derivation on committed pilot chains:
.venv/bin/python -c "
import json; from pathlib import Path
from swarm.arms_race import is_blue_detection, scoreboard
from swarm.population import Evolver
from redteam.reverify_floor import reverify as reverify_floor
chains = sorted(Path('data/live_arms_race/pilot_1337').glob('gen0_*.jsonl'))
chains = [c for c in chains if not c.name.endswith(('_io.jsonl','_telemetry.jsonl'))]
for p in chains:
    r = reverify_floor(str(p))
    ev = [json.loads(l) for l in open(p) if l.strip()]
    n = sum(1 for e in ev if is_blue_detection(e))
    truth = next(((e.get('data') or {}).get('blue_detections')
                  for e in ev if e.get('action') == 'duel.outcome'), None)
    print(p.name, 'floor_oos=', r.get('oos_executed'),
          'detections=', n, 'truth=', truth)
rr = iter(chains)
def _eval(g, seed):
    p = next(rr); return [json.loads(l) for l in open(p) if l.strip()], 0.0
E = Evolver(seed=1337, pop_size=3, side='red_live',
            ground_truth={'objective_host': 'db-core'})
print(E.tick(evaluate=_eval, eval_seed=1337))
"

# Unit-L loop-logic (Docker-free):
.venv/bin/python -c "from scripts.live_arms_race_run import _live_loop_selftest; _live_loop_selftest()"
```
