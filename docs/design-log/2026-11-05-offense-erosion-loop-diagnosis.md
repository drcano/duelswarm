# Offense-erosion diagnosis — a clear loop defect, but range-coupled (2026-11-05)

Time-boxed free-dry diagnosis of the offense-erosion curve the v2 paid run surfaced
(`docs/runs/2026-11-05-claim2-gen3-v2/`): corroborated crowns gen0=3/3 → gen1=2/3 → gen2=0/3,
"best_fitness" reported flat at 0.72. Dante's caveat going in: at pop=3, the 3→2→0 counts are
suggestive not firm (Fisher ≈ 0.05); the continuous fitness was expected to carry more signal.
Four mechanisms inspected: gated objective / reconciler, selection, mutation, variance.

## First: the "continuous fitness" carries NO extra signal on this run

`live_red_score_fitness = 0.40·gated_objective + shaping`. Re-derived per episode, **every one of
the 9 has the identical shaping sum 0.32**: depth=1.0 (≥3 hosts, capped), technique=0.0 (red events
carry **no `attack` label at all** — the axis is dead), exploit=0.8 (fixed 4 tools), stealth=0.0
(every episode trips 20–25 detections, capped), manipulation=0.0 (blue observe-only). So
`fitness = 0.32 + 0.40·achieved ∈ {0.32, 0.72}` — binary success in disguise. The fitness drop is
exactly the binary-win drop; Dante's n=3 caveat therefore stands at full force, and the shaping
terms meant to grade quality are all dead or saturated on this range.

## Mechanism C (reconciler / gated objective) — CLEARED, the failures are real

Per-episode spine vs verdict: every winner's dst-chain ends in an `exfil` state.mutate on db-core
(10.40.0.11) with `loot_corroborated=True`; every loser stops short — at db-bastion (10.60.0.11),
or reaches db-core with **no exfil mutate** (gen2_27c1e25cde0f), or only dba01 (gen2_4fb914dc5133).
`crown.access=0` on all episodes incl. winners, so the objective is driven by the exfil mutate +
loot corroboration, and it reads the spine correctly. The gen2 zeros are **genuine offense
failures** (red ran out the 44-turn budget before egress), not a reconciler false-negative. The
instrument is not misfiring.

## Mechanism B (selection) + A (mutation) — CONFIRMED, coupled

The run's own `Evolver` checkpoint (`red_live_archive.json`) shows it directly:

- **No live elitism.** `tick()` breeds `pop_size` children from the archive elites and sets
  `self.population = next_pop` — **all mutated children**. The proven 0.72 champion (the gen0
  "stealthy" ancestor) is retained only in archive cell `(0,0,2,1)` and **never re-run**:
  `inheritance_proofs=9` = every one of the 9 live episodes was a fresh mutated child.
- **`best_fitness()` returns the archive elite**, which is **monotone non-decreasing by
  construction** (`add` replaces only on strictly-higher qd). The dry negative control confirms it:
  stub `evolve()` (no LLM) gives best_fitness 0.32→0.32→0.87 / flat across seeds, never erodes. So
  the reported headline metric **structurally cannot show erosion** — the real erosion is in the
  **unreported live-population win-rate**.
- **Mutation steers off the one winning recipe.** `_shift_persona` (2 of 7 mutators) *replaces* the
  STYLE clause, so a winning child is jumped to a different persona ("minimal", "noisy-fast");
  other mutators append steering beats ("Stage loot in-scope before any egress", "Prefer in-scope
  lateral over new egress") and distilled lessons. With fitness binary (no in-cell quality
  gradient) and `_NOVELTY_LAMBDA`/`_EMERGENCE_BETA` actively **rewarding divergence from the
  playbook**, there is nothing to pull a drifting child back toward completion. Mutating the 0.72
  champion reliably yields a 0.32 loser, and selection never corrects it.

## Mechanism D (variance) — not answerable cheaply, and that itself is the finding

The erosion is live-LLM-specific: it is the model drifting off the tight kill chain under mutated
prompts on a turn budget. The deterministic dry stub does not model that, so the free harness cannot
reproduce it (the dry control above does the opposite — it climbs). At n=3 the live variance is
large and dominated by which elites the RNG picks as parents; the robust claim is **"mutating the
winner has a high failure rate on this range,"** not the specific 3→2→0 shape.

## Root cause: both defects are RANGE-coupled

On a one-entry / one-path range the single highest-fitness strategy is a tight, fast kill chain.
Exploration (novelty bonus, persona-shift, lateral/recon beats) is then **all cost and no benefit**,
and the loop has no second cell worth climbing to — so mutation looks purely destructive and offense
erodes. On a range that affords **more than one path to more than one crown**, that same exploration
pressure would discover new winning cells and the lateral/recon beats would have useful targets. The
loop's exploration machinery therefore **cannot be fairly evaluated — or a behavior-changing fix
validated — on this range**. This is the same root as the descriptor-saturation finding
(`2026-11-05-descriptor-v2-still-saturates.md`): the range affords exactly one recipe.

## Fixes, by weight

1. **Land now (cheap, no prereg amendment — pure instrumentation):** report the **live-population
   per-generation win-rate / mean fitness** in `live_generations_summary.json`, separately from the
   archive `best_fitness`. This is the metric that actually moved; today it had to be cold-derived
   by hand, and `best_fitness` (monotone) masked the erosion. Changes no selection; touches only the
   summary writer.
2. **Prereg amendment, validate on the claim-1 sweep (changes measured behavior):** add **live
   elitism** (carry the champion unmutated into the next population) and/or down-weight the novelty /
   persona-shift pressure so exploration does not dominate when one recipe wins. These change the
   measured co-evo loop → a dated amendment, not a unilateral edit, and they can only be fairly
   tested on a diversity-affording range.

## Recommendation

A clear mechanism surfaced, so under the brief this would say "fix it and re-run paid." But the fix
that matters is range-coupled: **re-running paid on this range — even with elitism — would not yield
a claim-2 gradient** (the descriptor still saturates, one recipe), so it would only green the offense
number, not measure the thing claim 2 is about. The productive next paid experiment is the **claim-1
floor-shape range sweep**, carrying the elitism / novelty amendment (fix #2) and the live-pop-fitness
instrumentation (fix #1) into it. That single run exercises the saturating descriptor axes, fairly
tests the loop's exploration, and pressure-tests the saturation finding — two findings for one run
cost. If, on a diversity-affording range, offense still erodes and the archive still collapses, *that*
is a firm negative about the co-evolution loop itself; today's is not yet, at n=3 on a one-path range.

## Artifacts

Scratch analyzers (not committed): per-episode spine-vs-verdict + fitness-term breakdown; dry
negative control. Loop code: `swarm/population.py` (`Evolver.tick` 945, `MapElitesArchive.add` 800,
mutators 110, `live_red_score_fitness` 286). Run: `docs/runs/2026-11-05-claim2-gen3-v2/`.
