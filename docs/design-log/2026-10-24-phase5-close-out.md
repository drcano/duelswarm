# Phase 5 close-out — finish the cut + D2/D4 onto exploit-per-hop; retire live_terrain

Date: 2026-10-24. Branch `real-range` (from `bca4c11`). The close-out increment. Commit 1 was a
verified no-op (its work already landed in batch one); the substance is commit 2. Nothing pushed.
No live/paid run — every live leg is a visible PENDING.

## Commit 1 — finish the cut: ALREADY SATISFIED at `bca4c11` (no-op, verified at source)
The brief's two loose ends were already closed by batch-one Phase 2 (the `real_struts_foothold`
extraction into `live_agent` + the seq 19/20 prereg amendments). Re-derived at source, not taken
on report:
- `grep -rn "live_swarm" scripts/*.py` → nothing. All three scripts already call
  `swarm.live_agent.real_struts_foothold` (`live_arms_race_run` imports `live_agent`;
  `measured_duel.py:500`; `prove_d2` now via the migration below). `swarm/live_swarm.py` does not
  exist; only `attic/` still references the name.
- `scripts/preregister.py --verify` → "chain OK (21 events); last anchor seq=20; all registered
  artifacts match the anchor" (rc=0). No `measured_duel.py` drift, so no new amendment was needed
  or invented.
No empty commit was fabricated for already-done work.

## Commit 2 — D2/D4 onto exploit-per-hop; retire live_terrain
- **Migrated `scripts/prove_d2_zoned_traversal.py` and `scripts/prove_d4_autonomous_agent.py`**
  off the retired credential-pivot terrain onto the engine's EXISTING exploit-per-hop enterprise
  crown spine, driving the ONE engine `live_agent.run_red_agent`. Both reuse the shared dry
  episode `arms_race_enterprise_frontier.dry_multihop_episode` (which drives `run_red_agent` turn
  by turn) — **no new module, nothing re-implemented**. Each asserts its distinct slice:
  - **D2** (zoned traversal): red reaches the crown at depth 2 with the crown pivot launched FROM
    the non-entry vantage `h1`; the out-of-scope pivot is gate-denied; floor `oos_executed=0` +
    chain verified cold by `reverify_floor`. No planted credential chain.
  - **D4** (autonomy): the one engine composes scan→exploit→pivot→loot to the crown over its own
    turns; discovery-driven (`verify_live_run` criterion 3 PASS); the live runner reconciles
    claims against the targets' own telemetry (source-level); floor `oos_executed=0` + chain cold.
  - **Live legs are visible PENDING** — `--selftest` runs the offline proof; the bare invocation
    prints a PENDING notice and boots nothing (no stub pass, nothing faked). The real D2/D4 live
    Docker boot is validated only in the gated combined paid pass (with the crown-depth-2 re-run).
- **Retired `swarm/live_terrain.py`** (deleted) and dropped its `make test` module-selftest line
  — coverage shrinking is correct. The literal/comment token was scrubbed from the two migrated
  proofs, `prove_d3` (a comment), and `swarm/live_traverse.py` (comments).
- **`swarm/live_traverse.py` is now ORPHANED** (nothing outside `attic/` imports its `walk`; it
  modeled the retired credential-pivot world). It does NOT import `live_terrain`, so the deletion
  does not break it; its selftest still passes and stays in `make test`. Retiring it is beyond
  this brief's scope — **flagged for Dante's review**, not silently removed.

## Done-checks at source (re-derive)
```
grep -rn "live_terrain" --include=*.py . | grep -v /attic/          # (nothing)
.venv/bin/python scripts/prove_d2_zoned_traversal.py --selftest     # PASS (offline)
.venv/bin/python scripts/prove_d4_autonomous_agent.py --selftest    # PASS (offline)
make test                                                           # green, range down; floor 0 oos MISSED
.venv/bin/python scripts/mediation/static_coverage.py               # PASS (no new ungoverned sink)
.venv/bin/python scripts/preregister.py --verify                    # clean (anchor seq=20)
```
The floor and the instrument are untouched by this increment: the migrated proofs re-derive
`oos_executed=0` + chain verified cold on the dry chains via `reverify_floor`.

## STOP
Phase 3.5 (tool authoring) and Phase 6 (two-population co-evolution) are NOT begun. The gated
combined paid pass (D2/D4 live boot + crown-depth-2 re-run) awaits Dante's explicit OK.
