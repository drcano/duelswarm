# Consolidation audit — re-derived at source (2026-10-27)

Independent audit of the cut (commits 7076a00 → ea3bbfe → 1429fff on real-range), done by re-staging
the post-cut tree and re-deriving the import graph cold — not by trusting `make test` green. Per CLAUDE.md,
readiness is re-derivation at source. Verdict: **structurally clean, one real defect to fix before we
build, plus one pre-existing housekeeping decision.**

## Clean (verified at source)
- **Deletion set matches the approved map exactly.** 28 scripts gone (parallel drivers, legacy counted
  path `prove_n2n3_tiered`/`prove_n3_live_blue`, the folded/obsolete proofs, peripherals) and 7 swarm
  modules gone (`blue_llm`, `blue_counter_recon`, `report`, `live_blue`, `orienteering`, `judge`,
  `deception`). Correctly kept: `prove_corpus_floor`, `prove_e2e_broad`, `sensor_stack`, the co-evo
  cluster + harness, `beacon`/`prove_sliver_c2`, `run_discovery_duel`'s users.
- **No dangling `from swarm import <deleted>` anywhere** — the targeted grep for deleted swarm modules
  returned zero real import statements (only comments/docstrings).
- **Instrument re-points landed correctly and are documented in-file.**
  `static_coverage.COUNTED_ENTRIES` = the three agent closures (`live_agent`, `live_red`,
  `live_blue_agent`), with the §E rationale written in (not `live_arms_race_run`, which imports the
  class-2 `uninstrumented` channel for the hard-floor probe). `leak_test.RED_ENTRYPOINTS` dropped the
  frontier entry. Neither oracle's logic changed.
- **`prove_one_engine` extended** with explicit GONE-files + GONE-modules assertions (one-of-each, and
  the deleted engines proven absent by import).
- **Makefile rebuilt correctly:** `test` now runs `swarm/live_red.py` (carries `prove_brick1`'s §2
  invariant) and `scripts/prove_engine.py --selftest` (the folded selftest); every deleted-file
  invocation is gone; the `viz`/`viz-dry`/`viz-replay` targets are removed.
- **The `wall` fixture producer survived the fold:** `prove_engine.fold_wall_fixture()` /
  `_wall_one_range()` write `data/wall/range_0.jsonl`, and run (test line 49) before the cold
  `reverify_floor` reads it (line 52) — so `make clean && make test` still has its input.
- **One engine / one duel / one range / one blue** hold structurally: `live_arms_race_run` →
  `run_interleaved_duel`; `topo_to_compose`; `live_blue_agent`; parallel engines deleted.

## DEFECT — must fix before building (introduced by the cut)
**`scripts/prove_control_reasoning.py:123`** — `from scripts.prove_d3_multiservice_foothold import
image_internal_port`, but `prove_d3` was deleted. It is a *lazy* import inside the H1 live-boot leg, so
the module still loads and `make test` (which doesn't run this script) stayed green — but the H1
reasoning-vs-recall live experiment will `ImportError` the moment it runs. **Fix:** relocate
`image_internal_port` (Docker image → internal-port discovery) into a kept module — `prove_engine.py`
is the natural home since it absorbed `prove_d3`'s multiservice invariant — and update the import. Then
re-run `prove_control_reasoning` far enough to confirm the import resolves.

## Cosmetic (non-breaking; tidy opportunistically, not blocking)
Stale docstring/comment mentions of deleted modules: `blue_fast.py:5` (→ `blue_llm`), `lineage.py:8`
(→ `analyze_lineage`), `host_egress_firewall.py:16` (→ `measured_duel`/`prove_n2n3`),
`live_agent.py:53` (→ `run_experiments`), `range_runtime.py:4` (→ frontier). No code path depends on
them. `static_coverage.MODULE_CLASS` also still lists now-deleted `deception`/`range_adversary` overrides
and stale `forensics`/`battlefield` — harmless (lookup only fires if the module is scanned), tidy later.

## Pre-existing open item (NOT caused by the cut) — corpus_floor on the confounded run
`prove_corpus_floor` re-derives the floor over every committed `docs/*.jsonl` with a scope event, and is
red on the `c540ddd` `full-run-1-confounded` log. That run was already **discarded/labeled CONTAMINATED**
(stale-telemetry blue confound; its floor + attacker readings held, blue detections thrown out).
`corpus_floor` already has two honest mechanisms: a **guarded exclusion-by-name** (the existing
`coevo_sweep_22gen` precedent — excluded only because its flagged ops are all documented authorized
`red→attacker_c2` beacons, with a guard that it still chain-verifies and flags nothing else), and
no-scope **sidecar skipping**.

Decision tree (needs CC to report the exact `reverify_floor.reverify()` output on that log FIRST —
`chain_verified`, `oos_executed`, and the `misses` targets — so we don't guess):
- **chain breaks, or a real unexplained out-of-scope execution** → that's a finding, recorded, not
  laundered. The run stays flagged; document why.
- **flagged ops are all documented-authorized** (C2 beacons / the known stale-telemetry artifact, with
  the floor + attacker intact) → it's a discarded/superseded run we don't stand behind, so the honest
  move is to get it **out of the certified corpus** — preferred: a principled "certify only runs we
  stand behind" rule (skip logs under a superseded/`sidecar` path), kept+labeled not deleted; acceptable:
  a guarded exclusion-by-name matching the `coevo_sweep_22gen` pattern, with a guard tailored to its
  flagged targets. Do NOT grow an unguarded exclusion.

My lean: it's a run we've already thrown out, so quarantine it out of the certified set rather than carry
an exclusion for evidence we don't stand behind — but confirm the failure mode before choosing.

## Bottom line
Fix the one dangling import (relocate `image_internal_port`), decide the corpus_floor item off CC's
reverify output, and the substrate is clean and honest — one engine, one of each, instrument frozen,
every invariant still exercised. Then we're clear to build the real capability (arsenal→live-path wiring,
a realistic range, real telemetry) on it.
