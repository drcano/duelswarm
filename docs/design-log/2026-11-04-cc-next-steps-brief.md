# Next-steps operational brief for CC (2026-11-04)

Authoritative handoff. CC executes every section in order; planner cold-verifies between each
section before the next starts. Dante has exactly one decision point in the whole flow — firing
the next paid run (Section 6). Everything else routes CC → planner-verify → CC.

The WHY for the descriptor change lives in
[2026-11-04-descriptor-redesign-brief.md](2026-11-04-descriptor-redesign-brief.md) (the finding,
the falsification, the axis reasoning). This brief is the HOW — the exact sequence, the
commands, the acceptance criterion per section.

## State at the start of this brief

- Nov 4 paid run cold-derived; both archives committed to `real-range` at `5c83360`
- `seq-50` anchored; `seq-51` and `seq-52` pending
- The behavior-descriptor 1/54 collapse is recorded as the first falsification the range caught
- `real-range` unpushed to `main` on the public repo — orthogonal to this work; Dante handles
  that on his own schedule

## Order of operations (strict; do not bundle sections)

---

### Section 1 — Bite test on the 9 committed Nov-4 chains (free, standalone)

**What to build.** `scripts/validation/descriptor_bite_test.py`. Stdlib-first; may import
`swarm/population.py` helpers only for `_red_allows` and `is_blue_detection` (axis derivation is
inlined so this script does not yet depend on a post-Section-3 `population.py`).

**What it does.** Loads the 9 committed Nov-4 chains from
`docs/runs/2026-11-04-claim2-gen3-paid/chains/`, applies the PROPOSED new `behavior_descriptor`
inlined in the script, prints `cells={N}` + the cell distribution across the 9 episodes, exits
0 iff `N >= 4`, non-zero otherwise.

**Axis derivation (from the chain, keyed on red's own actions — GT firewall holds):**

- **`path_idiom` (3 cells).** Walk red's `state.mutate(red, foothold|lateral)` events in `seq`
  order; collect the ordered sequence of `dst` names. Label:
  - `0 = canonical`: sequence starts with `[web01, dba01, db-bastion, ...]`
  - `1 = alt-dba`: sequence starts with `[web01, dba02, ...]`
  - `2 = off-seam`: anything else (including runs that never reach the crown)

- **`foothold_technique` (3 cells).** Find the first `(red, state.mutate, state=foothold)`
  event; read its `data.method` field and the immediately preceding `move.source(tool, cve)`.
  Label:
  - `0 = canonical-CVE`: `method` contains `S2-045` or `CVE-2017-5638`, or the preceding tool
    is `exploit` with the canonical CVE
  - `1 = msf-module`: `method` names any registered arsenal module other than the canonical
  - `2 = authored`: preceding tool is `author_tool`/`call_tool`

- **`turn_bin` (3 cells, archive-quantile).** Turn at which the first `(red, state.mutate,
  state=exfil)` OR the first telemetry-corroborated crown read occurs. Bin by quantile across
  the 9 chains at test time. Bootstrap rule for <9 observations: fixed thresholds — `early
  <=20`, `mid 21-33`, `late >33`. For an episode that never reaches the crown, assign
  `late` (grouped with late-but-successful attacks; honest for a run that burned budget).

- **`cred_idiom` (2 cells).** Count the distinct harvested credentials red actually consumed
  (from `driver.harvested_creds` — the SEQ50 Part 3 earned-cred path) before the crown read.
  Chain-derive this from the `(red, move.source, tool=pivot|loot)` events where red passed a
  specific cred:
  - `0 = bootstrap-only`: 0 or 1 distinct harvested cred consumed
  - `1 = chained`: 2+ distinct harvested creds consumed (legit-admin pattern)

**Acceptance.** `cells >= 4` on the 9 Nov-4 chains, AND the cell distribution is not degenerate
(no single cell holds >6 of 9 episodes — if 7+ chains land in one cell the axes still don't
separate what matters).

**Planner cold-verify.** Read the test's output; spot-check one chain by hand (walk its
`state.mutate` events, confirm the inferred `(path, technique, turn, cred)` tuple matches
observation); confirm `cells >= 4` and the distribution is reasonable.

**If bite test fails** (`cells < 4` or degenerate distribution): CC iterates the axes with
planner. Do NOT proceed to Section 2 until bite passes.

---

### Section 2 — `seq-51` anchor (paid-run state)

After Section 1 verified.

**What this anchors.** The state the Nov-4 paid run's committed chains were generated under:
- `swarm/llm.py` — pinned-provider rewrite (post Section-2 of the 2026-11-02 cleanup)
- `swarm/live_agent.py` — SEQ50 Part 2 (`assert_red_map_blind` extended to the episodic-memory
  channel)
- `swarm/live_red.py` — SEQ50 Part 3 (D1 earned-cred loot, fallback removed; C1 egress-mediated
  `run_command` reference)
- `swarm/live_blue_agent.py` — SEQ50 claim-3 blue activation (label-free, air-gapped, stealth
  triple, co-evolving)
- `swarm/topo_to_compose.py` — SEQ50 Part 1 held-out variant swap
- `scripts/mediation/static_coverage.py` — `swarm/intel` entry prune (post Tavily ripout)
- The remaining frozen-TCB files unchanged from seq-50

**What this does NOT anchor.** The new `behavior_descriptor` (seq-52), the three
prereg-manifest doc moves (seq-52).

**IMPORTANT: the three prereg-manifest docs stay at top-level `docs/` for seq-51.** That is
what the Nov-4 chains exercised. Moving them to `docs/archive/` NOW would retroactively rewrite
the manifest keys, recording a state the committed chains did not use. The moves ride seq-52
(Section 5).

**Run.**
```
.venv/bin/python scripts/preregister.py --rationale "Paid-run anchor: the state the first paid gen's committed chains exercised. Captures the llm.py pinned-provider rewrite, SEQ50 Parts 1-3 (held-out variant swap, GT-firewall memory extension, earned-cred loot + C1 egress-mediated run_command, blue mediated/air-gapped/stealth-triple/co-evolving), the Section-1 post-hackathon cleanup, and the swarm/intel static_coverage prune. Nov-4 paid run (pop 3 x gen 3, seed 1337, Nemotron Ultra, blue observe-only) cold-derived under this state: 3/9 corroborated crown thefts, floor oos=0 on 10/10 episodes (9 paid + 1 dry shakeout), provider pin held 10/10, IO sidecar 10/10, A-D1 recount matches outcome.blue_detections 10/10. The behavior descriptor's 1/54 collapse (all 9 paid episodes landed in cell (0,2,1,2)) is the first falsification the range produced; descriptor redesign anchors next under seq-52. See docs/runs/2026-11-04-claim2-gen3-paid/README.md and docs/design-log/2026-11-04-descriptor-redesign-brief.md."
```

**Planner cold-verify.**
- `seq-51` is the latest entry in `docs/prereg.jsonl`
- `scripts/verify_chain.py docs/prereg.jsonl` succeeds to `seq-51`
- Each file in `artifact_hashes` resolves to a current path with a matching sha256
- The `rationale` field is in-payload (present on the event's `data`)
- `make test` green (the previously deferred `preregister --verify` line now passes)
- `make verify` also green (same reason)

**Commit shape.** One commit, author `drcano@ucsd.edu`, message: `seq-51 anchor: paid-run state
(Nov-4 claim-2 gen3) with cold-derived chains + Nov-2 cleanup + SEQ50 Parts 1-3`.

---

### Section 3 — New `behavior_descriptor` in `swarm/population.py`

After Section 2 verified.

**Edit `swarm/population.py`:**

1. Replace `behavior_descriptor(episode_events, ground_truth=None)` body with the 4-D axes from
   Section 1 (the SAME computation the bite test used; do not drift). The function reads
   `episode_events` only — no `ground_truth` axis derivation (GT firewall).
2. Update `_BD_CARD = (3, 3, 3, 2)` — stays 54 cells, same archive size.
3. Update the `__main__` selftest: plant four synthetic episodes that differ in each axis one
   at a time (hold others constant), assert they land in four distinct cells. Plant a fifth
   that differs in two axes, assert it lands in a fifth distinct cell.
4. Keep the docstring honest: name the previous axes, name why they saturated on the unified
   seam range (one entry type, cap=2, impossible stealth, cap=2), and name the new axes.

**Do NOT edit the blue descriptor.** Blue is observe-only through claim 2; claim 3 is where
blue's descriptor matters.

**Run.**
```
.venv/bin/python swarm/population.py            # new selftest passes
.venv/bin/python scripts/validation/descriptor_bite_test.py --via-population
# ↑ now imports from swarm.population.behavior_descriptor instead of inlining;
#   result must still be cells >= 4 on the Nov-4 archive.
make test                                       # green
make duel-dry                                   # green
```

**Planner cold-verify.**
- New `population.py` reads clean; the function body does not reference `ground_truth`
- `__main__` selftest exercises the new axes with planted inputs
- Bite test via the committed code path returns `cells >= 4`
- `make test` + `make duel-dry` green
- `assert_red_map_blind` still passes in `make test` (the descriptor is measurement-only; it
  does not feed red's awareness)

---

### Section 4 — Three doc moves + `scripts/preregister.py` ARTIFACTS repoint

After Section 3 verified.

**Why bundled with seq-52.** The three docs (`COEVO_PREREGISTRATION.md`,
`EXPERIMENT_DESIGNS.md`, `PREREG_ENTERPRISE_ADAPTATION.md`) are referenced by
`scripts/preregister.py`'s ARTIFACTS at their top-level paths. Moving them to `docs/archive/`
and updating the ARTIFACTS keys is one coordinated change. It rides seq-52 so the amendment's
`--rationale` names both the descriptor change and the move, and the manifest refresh is a
single atomic update.

**CC:**
```
git mv docs/COEVO_PREREGISTRATION.md docs/archive/
git mv docs/EXPERIMENT_DESIGNS.md docs/archive/
git mv docs/PREREG_ENTERPRISE_ADAPTATION.md docs/archive/
# Edit scripts/preregister.py ARTIFACTS: update the three key paths to
# "docs/archive/COEVO_PREREGISTRATION.md" etc.
.venv/bin/python scripts/preregister.py --verify   # must succeed (ARTIFACTS resolves)
```

**Planner cold-verify.**
- Three files exist at `docs/archive/<name>.md`
- Zero `docs/COEVO_PREREGISTRATION.md`-shaped paths grep in `scripts/preregister.py`
- `preregister.py --verify` succeeds against the current state

**Commit shape.** One commit, `housekeeping: three prereg-manifest docs archived; ARTIFACTS
repointed to docs/archive/ paths`. Author discipline.

---

### Section 5 — `seq-52` anchor (descriptor redesign + bundled doc moves)

After Section 4 verified.

**Run.**
```
.venv/bin/python scripts/preregister.py --rationale "Behavior descriptor redesigned: old 4-D (entry, breadth, stealth, depth) saturated for every crown-reach on the unified seam range (Nov-4 paid run landed 9/9 episodes in cell (0,2,1,2), red_diversity=1/54). New 4-D (path_idiom, foothold_technique, turn_bin archive-quantile, cred_idiom) binds to signals that vary on red's chains; bite test on the Nov-4 archive via the committed code path reports cells>=4. Three superseded prereg-manifest docs (COEVO_PREREGISTRATION, EXPERIMENT_DESIGNS, PREREG_ENTERPRISE_ADAPTATION) archived to docs/archive/; ARTIFACTS keys repointed in the same amendment. Measurement-only change; GT firewall holds (axes keyed on red's own events, no ground truth); make test + make duel-dry green. Rationale for the descriptor redesign in docs/design-log/2026-11-04-descriptor-redesign-brief.md; operational handoff in 2026-11-04-cc-next-steps-brief.md."
```

**Planner cold-verify.**
- `seq-52` is the latest entry in `docs/prereg.jsonl`
- `scripts/verify_chain.py docs/prereg.jsonl` succeeds to `seq-52`
- `swarm/population.py` sha256 in artifact_hashes matches the current file
- Three doc keys resolve to `docs/archive/` paths with matching sha256
- Rationale in-payload
- `make test` green; `make verify` green

**Commit shape.** `seq-52 anchor: behavior descriptor redesigned (saturation on unified range
falsified); three prereg-manifest docs archived`.

---

### Section 6 — Ready for the next paid run (Dante's go)

Everything above complete and planner-verified.

**Next paid run spec** (fire on Dante's explicit go — token spend is the only decision that
routes through him):

```
make range-up                                   # if the range isn't still booted
with the Nebius API key set in the env: .venv/bin/python scripts/live_arms_race_run.py \
  --range unified --mode live --red-matched-tier \
  --live-generations 3 --pop-size 3 \
  --seed 1337 \
  --out data/live_arms_race/claim2_gen3_seed1337_v2
```

Same scale as Nov 4 (pop 3 × gen 3, seed 1337, blue observe-only, co-evolution ON). What
changes: measurement under the new descriptor.

**Planner cold-verify** (same discipline as Nov 4, plus descriptor-specific acceptance):

- Everything from Nov 4: `oos=0` per episode, verify_chain clean, provider pin held, A-D1
  recount == `outcome.blue_detections`, IO sidecar + telemetry sidecar complete, boot witness
  ok, floor held by construction
- **New: `red_diversity >= 4/54`** (the descriptor is not saturating) — acceptance for the
  redesign working
- **New: archive carries >= 4 distinct cells** by end of gen 3 (selection is doing work)
- **New: `best_fitness` varies across generations** (co-evolution has a gradient) OR flat
  reported honestly as the next finding
- Held-out transfer check: re-run against `docs/held-out/{app_crown_4hop, backup_route_5hop,
  mgmt_crown_3hop}` if any climbing red genome from the new archive is worth transferring —
  seam-dependence test for claim 1

Archive the run as `docs/runs/2026-11-04-or-later-claim2-gen3-v2/` with a cold `prove_*.py`
mirroring the Nov-4 pattern.

If the new descriptor still saturates: that's the next finding, filed as another dated
design-log entry, and the next iteration is finer axes or a different range.

---

## Commit discipline (binding on every section)

- One commit per operational unit. Do not bundle Section 2 into Section 3, Section 4 into
  Section 5, etc. — the per-section cold-verify needs clean commits to hash-check against.
- Commits author `drcano@ucsd.edu`; `[email redacted]` is the on-machine default
  and must be overridden per-repo. Sanity: `git log -1 --format='%ae'` after each commit.
- Commits authored `Dante Cano <drcano@ucsd.edu>`; no agent trailer on this repo.
- Nothing pushed by CC. The public-main push is Dante's at his own schedule, orthogonal.

## What CC does NOT do without planner approval

- Does not edit `swarm/population.py`'s descriptor before `seq-51` anchors.
- Does not move the three prereg-manifest docs before Section 4.
- Does not fire a paid run under any circumstance — token spend routes only through Dante
  (Section 6).
- Does not amend, force-push, or rewrite any entry in `docs/prereg.jsonl` — amendments are
  append-only.

## Planner verification cadence

After Section 1: bite test cell count + a spot-check of one inferred cell against a chain by
hand. After Sections 2, 3, 4, 5: the specific checks named in each section. The planner's
check is a NON-BLOCKING observation only on sections where CC has not written to the chain
(Sections 1, 3, 4); for chain-writing sections (2, 5), the planner's green is required before
CC proceeds to the next section.

---

## The posture, in one line

The Nov-4 run produced the first falsification the range caught: the measurement apparatus
isn't good enough to see what the research needs. This brief executes the fix, anchors both
states honestly (what the Nov-4 chains used, then what the next chains will use), and clears
the path to the next paid run with no routing through Dante until token spend.
