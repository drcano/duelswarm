# The seq-52 descriptor still saturates on a live run — and offense erodes (2026-11-05)

## The finding

The first paid co-evolution run under the redesigned behavior descriptor (seq-52:
`(path_idiom, foothold_technique, turn_bin, cred_idiom)`, 54 cells) **does not meet the acceptance
bar**. Same duel as Nov 4 (pop 3 × gen 3, seed 1337, Nemotron Ultra, blue observe-only, unified
seam range); the only change is the descriptor the archive is keyed on. Cold re-derivation
(`docs/runs/2026-11-05-claim2-gen3-v2/prove_claim2_gen3_v2.py`, both the committed
`swarm.population.behavior_descriptor` and the inlined bite-test reference, agreeing exactly):

- **Diversity: 3/54 cells, one cell holds 7/9.** `{(0,0,2,1):7, (0,0,2,0):1, (2,0,2,1):1}`. The
  Section-1 bite acceptance (`cells ≥ 4` AND no cell `> 6/9`) **FAILS**.
- **Two of the four new axes are constant across all 9 episodes.** `foothold_technique = 0`
  (canonical Struts CVE every time) and `turn_bin = 2` (late/never — every corroborated crown lands
  at turn 35–41, past the late threshold). Only `path_idiom` and `cred_idiom` moved at all, and each
  on exactly one of nine episodes.
- **Offense erodes across generations: corroborated crown thefts gen0=3/3 → gen1=2/3 → gen2=0/3.**
  Live best fitness 0.72 → 0.72 → 0.32. By gen2 every episode fails the gated objective. The
  archive's self-reported `best_fitness=0.72` is a *retained elite*, not the live population — the
  population drifted down, not up.

The instrument is sound on all 9 episodes (floor cold oos=0, chain verified, A-D1 parity, IO sidecar
complete, single Nebius pin, tier=ultra, boot witness rescued at attempt 2). A null result, not a
build failure.

## Why the redesign was correct and still didn't bite here

The redesign was validated against the Nov-4 archive and genuinely split it into ≥4 cells (the
Section-1 bite test, committed). That was not wrong. The Nov-4 chains *did* vary along the axes the
brief named — varied inner paths, varied crown turns (the brief cited "turn 18 vs turn 38"). This
run fired **under** the new descriptor and the variation the brief banked on did not materialize:

- every foothold was the canonical Struts CVE (no msf-module, no authored-tool foothold);
- every crown-reach was "late" (turn 35–41) — none of the early/mid spread the Nov-4 archive had;
- 8/9 took the identical canonical path web01 → dba01 → db-bastion.

Red's live repertoire on *this* range + model + seed is near-monomorphic. A descriptor can only
separate what varies, so a descriptor tuned on a more-varied archive still collapses when the
behavior underneath collapses. **The binding constraint on claim-2 diversity is the
range-plus-loop, not the descriptor's axis choice.** Two mechanisms, not mutually exclusive:

1. **The range affords one dominant recipe.** One exposed struts-class entry, one high-value path to
   the crown. The highest-fitness strategy is singular, so a fitness-seeking population converges on
   it. (This is the same saturation the Nov-4 entry diagnosed for the *old* axes — it is a property
   of the terrain, which the descriptor swap could not change.)
2. **The co-evolution loop neither produces nor retains diverse climbers.** Offense *eroding*
   3→2→0 while the elite is retained says selection/mutation is drifting the live population away
   from the one recipe that works, without discovering a second one. That is a loop defect
   (mutation operator, selection pressure, or the gated objective's shape), independent of the
   descriptor.

## Consequences for the experiment spine

- **Claim 2 (co-evolution produces an adaptation gradient) remains unsupported on this range.** Two
  paid runs now, two descriptors, both collapse. The honest read is that the *current range* does
  not afford the behavioral spread claim 2 needs — which is exactly what the claim-1 floor-shape
  sweep (ranges with more than one viable path to more than one crown) is for. Claim 2 should be
  re-measured on a range that affords diversity, not forced on this one.
- **Do not re-tune the descriptor again to chase 4/54 here.** That would be fitting the instrument
  to one run. The descriptor is pinned at seq-52; the next legitimate change to it is the claim-1
  range-adding amendment (where `_bd_path_idiom`'s hardcoded seam host names must generalize anyway
  — see the backlog note).
- **The offense-erosion curve is a separate, concrete loop defect** worth isolating on the free dry
  harness before the next paid run: reproduce 3→2→0 (or its dry analogue) and find whether it is the
  mutation operator, the selection rule, or the objective. Cheaper to debug unpaid.

## Artifacts

- Run + cold proof: `docs/runs/2026-11-05-claim2-gen3-v2/` (9 gzipped chains + io + telemetry + boot
  witness + `prove_claim2_gen3_v2.py` + README).
- Descriptor + archive code: `swarm/population.py` (anchored at prereg seq-52).
- Prior finding this supersedes-in-sequence (not in validity): `2026-11-04-descriptor-redesign-brief.md`
  (the Nov-4 1/54 collapse and the redesign) and `docs/runs/2026-11-04-claim2-gen3-paid/`.
