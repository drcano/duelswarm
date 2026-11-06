# 2026-10-30 co-evolution dry-gen verification — cold, zero spend

**Date:** 2026-10-30
**Branch:** real-range
**Scope:** 2026-10-30 co-evolution selection + erosion build brief, FREE dry-gen gate
**Command:**
```
.venv/bin/python scripts/live_arms_race_run.py \
    --live-generations 1 --pop-size 3 --mode dry \
    --out data/live_arms_race/cc_dry_1337
```
`--mode dry` → `use_llm=False` → the deterministic DryOODARouter drives red, zero tokens.
Range: the already-booted unified seam range (21 containers, seed 1337).

## What this run proves on the LIVE stack

A single FREE generation (seed 1337, pop 3, matched 44-turn budget) through
`run_live_generations` end-to-end — Falco attached live, boot witness, A1/A2/A5 gates,
A-D1/A-S1/A-S2/A-S3 all wired, B-M1/B-E1 recording, two auditors.

**Cold re-derivation output** (`prove_dry_gen.py`):

| Check | Result |
|---|---|
| A3 boot witness | `ok=True, auth=True, syscall=True, 7 Falco events attributed` |
| Floor (3 chains) | `oos_executed=0, chain_verified=True` on each |
| Auditor parity (3 chains) | `agree=True, single_boundary=True, missed_agree=True, scope_agree=True, oos_agree=True` on each |
| A-D1 predicate | `pred == duel.outcome.blue_detections = 10` on each chain |
| A-S1/A-S2 `Evolver.tick` | `pop=3, archive_entries=1, degenerate=0, excluded=0, best_fitness=0.1633` |
| Criterion #8 "selection occurred" | **GREEN** — the pre-build defect (`archive_entries=0`) is gone on the live stack |
| B-E1 persistent monitor | `m_g=1.0 (pre-refit), new_signatures=2`; curves recorded |
| Capability ceiling | wired (ceiling_depth=2, achieved=False — dry router doesn't own crown) |
| IO sidecar + telemetry sidecar | both chain-verified, 8 turn pins each, 7 turns full |

## Honest limits of a dry run (not a defect, documented in `prove_dry_gen.py`)

* `verdict.achieved=False` on all three chains — the deterministic DryOODARouter does not
  execute a telemetry-corroborated crown theft. This is expected: the dry router exercises
  the engine, not red's problem-solving. A paid gen is needed to score a corroborated win.
* `n_malicious=0, dwell_steps=None, recall=0.0` per episode — no red `state.mutate` into
  `{foothold, lateral, exfil}` landed, so there is no dwell window to measure. The B-E1
  dwell is reported as `None` (not silently zeroed) and n_malicious=0 → recall defaults
  to 0.0. These are the "honest NULL" semantics the committed pre-reg's criterion #8 preserves.
* `red_cells=1, red_diversity=0.0185` — three dry chains collapsed to one behavior cell
  under MAP-Elites' 4-D descriptor. The deterministic router produces nearly identical
  action shapes across genomes. Paid gen (Nebius red) is what exercises diversity.

## What was NOT run and why

* **Paid generation.** Gated on Dante's go per the build brief. The dry gen's job is to
  confirm the live stack carries the committed selection + erosion wiring (it does); the
  paid gen is where B-M1's distilled lesson flows through episodic memory on a chain that
  can actually win, and where the erosion curve picks up a non-trivial recall > 0.
* **seq-51 anchoring.** Deliberately deferred per the pre-reg; anchors on the code the
  scored paid run actually uses, after Dante's cold re-derivation.

## Files in `./chains/`

* `boot_witness.jsonl` — the one-line `boot.witness_check` the A3 witness emits
* `gen0_*.jsonl.gz` — the three per-episode hash-chained main logs
* `gen0_*_io.jsonl.gz` — the IO sidecars (what red sent / what the range returned)
* `gen0_*_telemetry.jsonl.gz` — the per-episode telemetry sidecars (Falco + conntrack + service)
* `live_generations_summary.json` — `run_live_generations` return + per-gen history
* `red_live_archive.json` — the MAP-Elites archive after this one generation

All text files are UTF-8 JSONL, hash-chained; the `*.jsonl.gz` are standard gzip of the
original JSONL. `prove_dry_gen.py` ungzips to a temp dir and reads them.

## Reproduction

```bash
.venv/bin/python docs/runs/2026-10-30-coevo-dry-gen/prove_dry_gen.py
```

Needs only the repo (no Docker, no API key).

## Commits in this verification window

```
e8eea90  A-S2 docstring: honest about ownership vs reach altitude
```

(the dry gen itself produced no code change; the archived run is the verification artifact)
