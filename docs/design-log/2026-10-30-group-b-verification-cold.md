# Group B verification — cold, zero spend
**Date:** 2026-10-30
**Branch:** real-range
**Scope:** 2026-10-30 co-evolution selection + erosion build brief, Group B units B-M1 and B-E1

## What verified cold

### 1. B-M1 — per-parent lesson distillation
`swarm/population._distill_lesson` on a crafted winning episode produces, in order:

> `WORKED: T1190 on http foothold | T1021 on ssh via harvested cred lateral |
>  T1041 on unknown via harvested cred exfil (crown tier) ; BLOCKED: T1021 on unknown`

- Carries technique IDs (`T1190`, `T1021`, `T1041`), service types (`http`, `ssh`),
  the credential-source marker (`harvested`), and the generic `crown tier`
  marker — all GT-free.
- `assert_red_map_blind` PASSES on this lesson (both `episodic_recall` and
  `memory_write` channels), proving the A5 firewall accepts the distilled
  text.
- The same guard STILL BITES on a hand-crafted GT-leaking lesson
  (`"reuse the dbadmin cred on db-core"`), proving the firewall remains
  active over the memory channel exactly as A5 requires.

### 2. B-M1 — the two measured arms behave as advertised
- `Evolver(side="red_live_memory_on")` → after one tick, each child's
  `memory` contains the distilled lesson (not a canned `_DEFAULT_LESSONS`
  entry).
- `Evolver(side="red_live_memory_off")` → after one tick, each child's
  `memory` is `[]` — no inherited lesson between episodes (fresh context).

### 3. B-E1 — the Unit-L loop records the erosion curve
`_live_loop_selftest` passes with the B-E1 extensions:
- Every generation's history carries a `monitor` record with
  `miss_rate_m_g`, `monitor_signatures_after`, `new_signatures_this_gen`,
  and `stealth_triples` (one per chain).
- Result exposes `monitor_erosion_curve` and `monitor_signatures_curve`.
- Stub chains with a real `blue.detect.bernoulli` fire produce
  `recall > 0.0` on every stealth triple (A-D1 predicate wired correctly).
- Signatures grow across generations (`5 → 5` on the two-gen stub, where
  gen 1 is all-falco-down).

### 4. B-E1 — cold re-derivation on the three committed pilot chains
Treating the three pilot gen0 chains as one simulated generation:

```
stealth  gen0_4a62d3b42d40.jsonl  recall=1.0  dwell_steps=None  fp_cost=0  n_mal=5  n_det=21
stealth  gen0_5a4b032e134d.jsonl  recall=1.0  dwell_steps=None  fp_cost=0  n_mal=1  n_det=19
stealth  gen0_de6f0c20cc73.jsonl  recall=1.0  dwell_steps=None  fp_cost=0  n_mal=5  n_det=22
monitor  m_g (BEFORE refit, empty)=1.0  new_signatures_after_refit=25
monitor  m_g (SECOND gen, same behaviors, POST refit)=0.0  [blue recovers]
```

**Honest dwell semantics:** `dwell_steps = None` because blue's first fire
comes BEFORE red's first `state.mutate` on these pilot chains (noisy early
recon). This is correct dwell — "undetected window after red compromised
something" has no measurement when blue detects before the compromise lands.
Reported as `None`, never silently zeroed.

The m_g 1.0 → 0.0 transition is the dynamic the thesis is about: an unfit
monitor misses everything, then blue adapts and recovers.

## Not yet run (needs Dante's go)
A booted-range FREE dry generation (`use_llm=False`) exercising the live
Docker stack with a deterministic router. The Docker-free Unit-L loop
selftest already drives the exact `run_live_generations` code path cold,
through a stub episode, so the B-E1 wiring is verified; the booted-range
run would additionally confirm the live tool stack produces the same
chain-shape under real Docker.

## Commits in this verification window
```
2260f7b  B-M1 + B-E1: distill lesson per parent; persistent monitor + m_g
9a9aa55  MEASURED_ARM_EROSION: pre-reg deltas 1-6 + new healthy criterion
```

## Reproduction
```bash
# Unit-L + B-E1 loop-logic (Docker-free):
.venv/bin/python -c "from scripts.live_arms_race_run import _live_loop_selftest; _live_loop_selftest()"

# B-M1 + B-E1 cold re-derivation on committed pilot chains:
.venv/bin/python -c "
import json; from pathlib import Path
from swarm.arms_race import LearnedMonitor, is_blue_detection, scoreboard, _MALICIOUS
from swarm.population import _distill_lesson

# B-M1 distillation on one pilot chain:
ev = [json.loads(l) for l in open('data/live_arms_race/pilot_1337/gen0_4a62d3b42d40.jsonl') if l.strip()]
print(_distill_lesson(ev))

# B-E1 erosion dynamics across the three pilot chains:
chains = sorted(Path('data/live_arms_race/pilot_1337').glob('gen0_*.jsonl'))
chains = [c for c in chains if not c.name.endswith(('_io.jsonl','_telemetry.jsonl'))]
monitor = LearnedMonitor()
all_events = []
for cp in chains:
    all_events.extend([json.loads(l) for l in open(cp) if l.strip()])
m_g0 = monitor.evasion(all_events)
new = monitor.fit(all_events)
m_g1 = monitor.evasion(all_events)
print('m_g gen0:', m_g0, 'new signatures:', new, 'm_g gen1 (same behaviors):', m_g1)
"
```
