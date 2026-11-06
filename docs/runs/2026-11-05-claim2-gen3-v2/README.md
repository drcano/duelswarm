# 2026-11-05 — claim-2 pop3×gen3 PAID v2 (first run under the seq-52 descriptor)

The first paid co-evolution run fired **under the redesigned behavior descriptor** anchored at
prereg **seq-52** — `(path_idiom, foothold_technique, turn_bin, cred_idiom)`, `_BD_CARD=(3,3,3,2)`,
54 cells. It re-fires the exact duel the 2026-11-04 run did (pop 3 × gen 3, seed 1337, red matched
tier = ultra, blue observe-only, unified seam range), the only change being the descriptor the
MAP-Elites archive is keyed on.

- **Provider:** Nebius Token Factory, Nemotron, tier=ultra throughout (single pin, re-derived).
- **Range:** unified seam range, seed 1337 (`make range-up-unified`).
- **Out dir (source):** `data/live_arms_race/claim2_gen3_seed1337_v2/`.

## Cold re-derivation — `prove_claim2_gen3_v2.py`

Re-derives every number from the raw gzipped chains with the floor's own verifier tools. The run's
`live_generations_summary.json` is spot-checked at the end, never trusted for a verdict.

```
.venv/bin/python docs/runs/2026-11-05-claim2-gen3-v2/prove_claim2_gen3_v2.py
```

### Instrument — SOUND on all 9 episodes (holds by construction)
- `verify_chain` clean; `reverify_floor` **oos_executed=0 & chain_verified** on every episode.
- `auditor_parity` (A-D1) agrees with the floor on oos count / scope / misses, every episode.
- `verify_io_sidecar` complete (every turn pinned, no dangling/duplicate).
- `verify_provider_pin`: single Nebius pin, every `llm.call` on the pinned lineage, **tier=ultra**.
- A-D1 unified predicate `sum(is_blue_detection) == duel.outcome.blue_detections` holds exactly.
- Provenance: 39–52 LLM-driven moves/episode, **0 silent fallbacks, floor HELD**.
- Boot witness: ok, auth + syscall witnessed (14 attributed), rescued at attempt **2/6** (the
  eBPF-attach-race fix bit again — recorded, not hidden).

### Offense (a RESULT, not a gate) — strong but ERODING
- **5/9** crown thefts (`verdict.achieved`), **all 5 reconciler-corroborated**.
- Per generation: **gen0 = 3/3, gen1 = 2/3, gen2 = 0/3**. Offense decays across generations.
- Live best fitness per generation: **0.72 → 0.72 → 0.32**. By gen2 every episode fails the gated
  objective (fit 0.32). The archive's reported `best_fitness=0.72` is a **retained elite**, not the
  live population — the live population drifted *down*, not up.

### Diversity NULL #2 — the seq-52 descriptor still saturates HERE
- Re-derived over all 9 chains (committed `swarm.population.behavior_descriptor` **and** the
  inlined reference agree exactly): **3/54 cells**, one cell holding **7/9**.
- Histogram: `{(0,0,2,1): 7, (0,0,2,0): 1, (2,0,2,1): 1}`.
- Section-1 bite acceptance (`cells ≥ 4` AND no cell `> 6/9`): **FAIL**.
- **Two of the four new axes are constant** across all 9 episodes: `foothold_technique = 0`
  (canonical struts CVE every time), `turn_bin = 2` (late/never — every corroborated crown lands at
  turn 35–41, past the late threshold). Only `path_idiom` and `cred_idiom` moved, each on exactly
  one episode.
- The archive's self-reported `red_cells=2` differs from the raw bite's 3 only because the failed
  off-seam episode `(2,0,2,1)` (fit 0.32) never entered the competitive archive. Both are below 4.

## What this run establishes

The descriptor redesign was **correct for what it was validated against** — the more-varied Nov-4
archive split into ≥4 cells. It did **not** fix the underlying fact this run exposes: red's live
repertoire on *this* range + model + seed is near-monomorphic (canonical struts foothold → canonical
web01→dba01→db-bastion path → late crown), so there is almost nothing for *any* descriptor to
separate, and the co-evolution loop has no gradient to climb — worse, it erodes. The acceptance bar
(`red_diversity ≥ 4/54`, archive ≥ 4 cells, fitness climbing) is **not met**, reported honestly.

Filed as the next finding in `docs/design-log/2026-11-05-descriptor-v2-still-saturates.md`. No
held-out transfer check was run: nothing climbed, so there is no improving genome to transfer.
