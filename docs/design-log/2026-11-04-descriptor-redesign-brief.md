# Behavior-descriptor redesign — the paid-run finding + the fix (2026-11-04)

## The finding

The Nov 4 paid run (pop 3 × gen 3, blue observe-only, seed 1337, Nemotron Ultra) produced a
genuine claim-2 result at the point level — 3/9 corroborated crown thefts, floor held 10/10 by
construction, provider pin held, air-gap held. It also produced the first intended falsification
the range caught: the 4-D behavior descriptor collapses all 9 episodes to one cell (0,2,1,2) of
54. `red_diversity = 1/54 = 0.0185`. Best fitness pinned at 0.72 from generation 0. No gradient,
no erosion curve, no claim-2 dynamic measurement.

The Oct 30 dry-gen archive predicted this (red_cells=1 with a deterministic router, blamed on
the stub) and projected "paid Nebius red is what exercises diversity." It does not. The real
Nemotron red lands in the identical cell at the identical diversity. That prediction is
falsified in the chain, and the finding is recorded here.

**The defect is in the descriptor, not the attacker.** Every axis saturates on this range for
any attack that actually reaches the crown:

- `entry_bin` saturates: web01 is the only exposed entry (struts-class).
- `breadth_bin` saturates at cap=2: any successful attack uses recon + exploit + harvest +
  pivot + loot — at least 4 distinct tools.
- `stealth_bin` saturates at "noisy": the `≤1 detection` threshold is impossible on a 44-turn
  attack against real Falco telemetry (every episode fires 21-25 detections, stealthy persona
  included).
- `depth_bin` saturates at cap=2: a crown-reach touches at least web01 → dba0X → db-bastion →
  crown — three non-entry hosts.

Three behaviorally distinct wins across three generations collapse to the same cell because the
axes can't see what differs about them.

## What actually differs across the 9 chains (chain-derivable, keyed on red's own actions)

- **Which inner path.** Some episodes go web01 → dba01 → db-bastion → crown; others go through
  dba02; others touch app-fs or a different intermediate. The ordered sequence of compromised
  hosts.
- **Primary foothold technique.** Canonical Struts CVE-2017-5638 vs msf-module vs an authored
  tool. The `method` field on the first successful `foothold` mutation.
- **Turn to crown.** Some episodes crown-read by turn 18, others by turn 38. Highly variable
  across LLM runs; the engine records turn count directly.
- **Credential idiom.** Bootstrap-cred-only (one-hop reuse) vs chaining through legit-admin
  (svc_dba harvested from dba01 then reused). The credential_graph edges red actually walked.

Every one of these varies on the committed chains, every one is derivable from events already in
the chain (no ground truth, GT firewall holds), and every one is behaviorally meaningful to the
research (path idiom tests seam dependence; technique tests capability mix; turn-to-crown tests
efficiency; credential idiom is precisely what SEQ50 Part 3's earned-cred discipline was
designed to make measurable).

## Proposed new descriptor (4D, 54 cells — same archive size)

```python
_BD_CARD = (3, 3, 3, 2)   # path_idiom, foothold_technique, turn_bin, cred_idiom
DESCRIPTOR_CELLS = 3 * 3 * 3 * 2  # 54
```

**Axis A — path_idiom (3 cells).** The sequence of first-N compromised inner hosts, keyed on
observed names:
- 0 = canonical (web01 → dba01 → db-bastion → crown_host)
- 1 = alt-dba (web01 → dba02 → db-bastion → crown_host)
- 2 = off-seam (any other ordered sequence that reaches the crown — app-fs, backup, etc.)

Derived from red's own `state.mutate(red, foothold|lateral)` events, ordered by seq. No ground
truth; the "canonical" and "alt-dba" labels are STRING COMPARISONS against red's recorded dst
names, and a reviewer re-derives them cold.

**Axis B — foothold_technique (3 cells).** The method red used to pop the first inner host:
- 0 = canonical CVE (CVE-2017-5638 or the arsenal's registered first-hop module)
- 1 = msf-module (an arsenal-registered module other than the canonical one)
- 2 = authored (`author_tool` + `call_tool` path)

Derived from the `move.source` event on the first-inner-hop turn: `tool` and the `method` field
on the resulting `foothold` mutation.

**Axis C — turn_bin (3 cells, archive-quantile).** The turn at which the first crown-read
occurs, binned by the ROLLING ARCHIVE QUANTILE (not a fixed threshold, so the bins adapt as the
archive grows):
- 0 = ≤33rd percentile across the archive (early)
- 1 = 33rd–66th percentile (mid)
- 2 = >66th percentile (late)

For an episode that never reaches the crown, assign turn_bin=2 (the attack ran long and did not
convert; same cell as a late-but-successful attack is acceptable since failure is also a "late
+ no result" shape; or we add a fourth bin for no-crown — call this as the implementation
decision). The quantile is computed over the archive at the time the descriptor fires (the
first few entries fall into fixed bins until the quantile is well-defined — CC decides the
bootstrap rule).

Derived from the chain event where `(red, state.mutate, state=exfil)` or the equivalent crown-read
marker first appears. No ground truth.

**Axis D — cred_idiom (2 cells).** Whether red reached the crown via bootstrap-cred alone or
through a legit-admin chain:
- 0 = bootstrap-only (at most one harvested credential consumed before the crown read)
- 1 = chained (≥2 harvested credentials consumed; the SEQ50 Part 3 earned-cred path)

Derived from the ordered sequence of `_pivot_candidates()` consumptions and the
`driver.harvested_creds` red actually used.

## Why this does not saturate

- Path_idiom varies across the 9 committed chains (Nov-4 archive README likely enumerates
  this; CC confirms before the switch).
- Foothold_technique has three real alternatives on the current range: canonical CVE, two
  arsenal modules, author_tool.
- Turn_bin is archive-quantile — it varies by construction once ≥3 entries exist.
- Cred_idiom distinguishes the SEQ50-Part-3-exercising wins from bootstrap-only wins.

**Bite test (free, do this before the amendment):** apply the new descriptor to the 9
committed chains from the Nov-4 paid run. If they still collapse to ≤2 cells, the axes are
wrong and we iterate. If they spread across ≥4 cells, the fix works. This is cold-provable on
the committed archive; costs zero paid spend.

## GT firewall

Every proposed axis is keyed on red's OWN observations + chain events:
- Axis A compares to string host names red discovered and owned (not a scope list).
- Axis B reads red's `move.source.tool` and the `foothold.method` red's action produced.
- Axis C reads the turn index and the archive's own quantile (not GT).
- Axis D reads red's `harvested_creds` consumptions (red's own state).

`assert_red_map_blind` already covers the per-turn awareness channel. The descriptor is
computed POST-episode, not fed into red's inputs, so it's measurement-only.

## What this is NOT (keeping the brief honest)

- Not a fix that makes red "win more." The descriptor change is measurement; the attacker is
  unchanged. 3/9 corroborated thefts stay 3/9; floor stays `oos=0`.
- Not a backfit to the committed chains. The axes were selected from WHAT DIFFERS GENERALLY
  across real-range attacks (path, technique, time, credential chain), not from what would
  make the 9 Nov-4 chains spread. The bite test on those 9 is a sanity check, not the
  justification.
- Not a solve for claim 1 and 3. Claim 1 (floor-shape → red's evolved path) needs varying
  floor shapes; claim 3 needs blue active. Both are downstream; this unblocks the measurement
  infrastructure both depend on.

## Amendment plan — two amendments, not one

Current state: seq-50 is anchored. seq-51 was deferred to "the first paid run," which just
happened. seq-52 is the descriptor change.

### seq-51 — the paid-run state the Nov-4 chains used (lands first)

Anchors what the committed Nov-4 chains exercised. **No descriptor change here.** Includes:
- `swarm/llm.py` — the pinned-provider rewrite (Section 2 of the Nov-2 cleanup)
- Four SEQ50 artifacts (Part 1 held-out swap, Part 2 GT-firewall memory extension, Part 3
  earned-cred loot, +C1 egress-mediated run_command)
- `scripts/mediation/static_coverage.py` — the `swarm/intel` entry prune
- Three prereg-manifest doc path moves (COEVO_PREREGISTRATION, EXPERIMENT_DESIGNS,
  PREREG_ENTERPRISE_ADAPTATION → docs/archive/) + the corresponding ARTIFACTS repoint in
  `scripts/preregister.py`

Rationale (`--rationale`): "Paid-run anchor: the state the first paid gen's committed chains
exercised. Ride-along manifest refresh for the Nov-2 cleanup + SEQ50 Parts 1-3 + the three
prereg-manifest doc moves held off until paid-run cold re-derivation."

Lands NOW based on the just-finished paid chains being cold-derived.

### seq-52 — the descriptor redesign (lands before the next paid run)

Anchors `swarm/population.py` with the new `behavior_descriptor` + the (3,3,3,2) `_BD_CARD`.
No chain impact on the Nov-4 run (its chains stay valid; the old descriptor they were scored
under was correct code at the time).

Rationale: "Behavior descriptor redesigned: old 4-D (entry, breadth, stealth, depth) saturated
for every crown-reach on the unified seam range; new 4-D (path_idiom, foothold_technique,
turn_bin archive-quantile, cred_idiom) binds to signals that actually vary on the chains red
produces. Falsification of the Oct 30 dry-gen prediction that paid Nemotron would exercise
diversity under the old descriptor is recorded in the Nov 4 run archive."

## Cold re-derivation on the next paid run

Same stack as Nov 4 plus:
- The 9 old chains re-scored under the new descriptor reach ≥4 distinct cells (bite test;
  free; prerequisite to seq-52).
- The next paid run (pop 3 × gen 3) produces ≥3 distinct cells across its 9 episodes.
- `best_fitness` moves across generations (not pinned at gen 0's value), OR if it doesn't, the
  flat curve is reported honestly as the measured erosion signal under the new descriptor.
- `red_diversity` reports ≥ 4/54 at the end of the run; the collapse mode has been ruled out.

If any of those fail, we've measured something real — the descriptor still isn't catching
what matters, and the next iteration is the finding.

## The two things I will NOT do unilaterally

- Edit `swarm/population.py` (measurement-path; requires the seq-52 amendment first).
- Anchor seq-51 (the paid-run amendment belongs to Dante with the explicit rationale).

## Acceptance for CC

1. Land the bite-test script under `scripts/validation/descriptor_bite_test.py --selftest` that
   re-applies the proposed descriptor to the 9 committed Nov-4 chains and prints
   `cells={<count>}`. Free, cold-reproducible, stdlib-preferred.
2. If the bite test reports ≥4 cells: write the seq-52 amendment draft (uncommitted) with the
   rationale text above; I cold-verify; Dante anchors.
3. Land the new `behavior_descriptor` in `swarm/population.py` on `real-range`; I cold-verify
   TCB hashes (new population.py sha matches the seq-52 anchor), make test + make duel-dry
   green, bite test passes, descriptor cells on the committed Nov-4 chains report ≥4.
4. After seq-52 anchors, fire the next paid run (pop 3 × gen 3, same seed, same range, same
   budget). I cold-verify everything from Nov 4 PLUS the new red_diversity ≥ 4/54 acceptance.

## Timeline

Bite test + seq-52 draft tonight (free). Seq-51 anchoring at Dante's bandwidth. Seq-52 anchor
after bite test passes. Next paid run on Dante's go. The result of that run is what either
produces the erosion curve or files the next finding.
