# Phase 6 — red AND blue as co-evolving populations (+ mandatory fix #4)

Date: 2026-10-24. Branch `real-range` (from `dd67d04`). Dry/offline only; the paid multi-generation
LIVE co-evolution run is credit-gated and NOT run (a visible PENDING in the loop). Nothing pushed.

## Genome extended — `{prompt, memory, authored_tools}` (swarm/population.py)
`Genome` gains `authored_tools: dict` (the Phase-3.5 tools a lineage invents). A child inherits
its parent's toolbook (copied, not aliased) through `mutate`; it round-trips through
`save`/`restore` (serialized via `asdict`, rebuilt via `Genome(**g)`, old checkpoints default to
`{}`). `hash` stays prompt+memory, so provenance and existing checkpoints are stable — an added
field + its inheritance, not a rewrite. Evolution now selects over strategy AND invented tooling.

## One population module, parameterized by `side` (swarm/population.py)
No second population module. A `SideSpec` bundles everything that differs between sides (personas,
prompt seed, `score_fitness`, `behavior_descriptor`, cells, mutators, lessons); `SIDES = {"red",
"blue"}`. `Evolver(side=...)` reads its scoring/descriptor/personas/seed from the spec — `side="red"`
is byte-identical to before (back-compat). Added for blue:
- `_BLUE_PERSONAS` (tripwire / surgical / aggressive-contain / crown-guard / patient / broad-sensor).
- `blue_behavior_descriptor`: detection-breadth × containment-aggressiveness × FP-cost ×
  crown-protected (36 cells), telemetry-derived.
- `blue_score_fitness`: sourced ONLY from telemetry — crown held vs lost, detection recall over
  red's spine-confirmed malicious actions, IR-scoreboard containment speed (MTTC) and low dwell;
  never a blue self-report.
Import graph: `population.py` is the sole population module; its importers (`coevolve.py`,
`scripts/live_gates.py`) use it.

## Mandatory fix #4 — selection reads confirmed telemetry, never a self-report
- `manipulation_score` rewired off red's `red.deception.summary` onto BLUE's OWN logged
  `detect.posture` (how far blue's peak attention sits above its attention on the true objective).
- `score_fitness` objective rewired off the dead cascade names onto spine-confirmed events
  (`crown.access` + `state.mutate` state 'exfil'); `_ENTRY_CLASS` + the dry stub rekeyed to the
  real engine vocabulary; `detect.posture` excluded from the stealth detection count.
- `arms_race._MALICIOUS` and `scoreboard`'s compromise detection rewired off the cascade names
  onto the spine (`state.mutate` foothold/lateral/exfil, `crown.access`); selftests updated.
- Grep: `db_exploit|enumerate_db|exfiltrate` → nothing in `population.py` / `arms_race.py`;
  `deception.summary` → only the NEGATIVE test asserting a red self-report never moves fitness.

## Two-archive co-evolutionary loop (swarm/coevolve.py)
`coevolve_populations(...)`: a RED MAP-Elites population and a BLUE one (one `Evolver`,
side-parameterized) each evolve against the OTHER's current elite, generation by generation; both
archives checkpoint after every generation (resume continues, no recompute). `dry_duel(red_genome,
blue_genome, seed)` is the offline episode — spine-confirmed red moves, blue detections/posture/
containment, the only out-of-scope move a `gate.block`, so the floor is 0 by construction. The
deterministic gate holds flat at 0 every episode — that INVARIANT is the reported result, not
"co-evolution works". `coevolve`'s deterministic `run_coevolution` + `arms_race.LearnedMonitor`
are now explicit ABLATION BASELINES.

## Done-checks at source (dry, offline; re-derive)
```
.venv/bin/python swarm/population.py    # red + blue MAP-Elites on one Evolver; genome authored_tools inherited; fix-#4 fitness
.venv/bin/python swarm/arms_race.py     # learned-monitor + scoreboard on spine-confirmed vocab; gate flat at 0
.venv/bin/python swarm/coevolve.py      # baseline + two-population: 1v1 + NvN dry duels, checkpoint/resume, gate flat at 0
grep -nE "db_exploit|enumerate_db|exfiltrate" swarm/population.py swarm/arms_race.py   # nothing
grep -nE "deception\.summary" swarm/population.py   # only the negative test
make test                               # green, range down
.venv/bin/python scripts/mediation/static_coverage.py   # PASS
```

## PENDING (credit-gated)
The paid multi-generation LIVE co-evolution run (swap `dry_duel` for a real booted-range duel)
is credit-gated — the loop is built, NOT run at scale. Stated as a visible PENDING in
`coevolve_populations`' docstring.

## STOP
Phase 6 is the last build in this track. Nothing beyond it begun.
