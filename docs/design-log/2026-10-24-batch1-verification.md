# Batch-one + close-out verification — independent re-derivation (gates batch two)

Date: 2026-10-24 (updated through `a790bcf`)
Author: the planning/verifier session, with Dante.
Branch `real-range`. Covers `126f1d9` (cleanup), `327befe` (P1), `5c0b599` (P2), `727fa4c` (P2.5),
`06e4d58` (P3), `7a42b5c` (P4a), `f87b7fa` (P4b), `bca4c11` (P5 offline), `a790bcf` (D2/D4 close-out).

## Method
File-only bridge (no shell/Docker on the build host): the tree is staged into an isolated
container and headless done-checks re-derived there — greps, the keepers' own selftests, the cold
floor auditor, `preregister.py --verify`. Live legs (real C2, real Docker boot, paid LLM runs) are
NOT re-derivable here and are marked as such. METHOD CORRECTION (see errata): absence-greps and
selftests must be run against files RE-STAGED immediately beforehand — a stale staging mirror
caused two false findings in the first draft of this doc.

## VERIFIED (re-derived at source / by execution)
- One of each: exactly one `run_red_agent`, one `BlueAgent`, one effect primitive `gate.run_effect`,
  one `Gate`. P1 cheat-sheet gone tree-wide; `live_weapon` selftest green.
- P4b one effect path: the only `subprocess.` sink in `swarm/` outside `gate.py` is the deliberate
  `uninstrumented.py` falsifier; every real effect routes through `gate.run_effect` under
  `gate.dispatch`.
- P4a verb axis: gate selftest green (read-allowed / mutate-denied, confused-deputy caught).
- P2 / P3 engines run their selftests; P2.5 Sliver wiring selftest green (`beacon.py` a real
  callback, foothold confirmed from the C2's record, oos C2 recorded, T1071, floor oos=0).
- wall.py adversarial oos-probe present (gate blocks, not a trivial pass).
- Floor: `reverify_floor` → oos=0 + chain verified on fresh current-engine chains; falsification
  battery still bites; `redteam_gate`, `prove_spine` green.
- Close-out `a790bcf`: `prove_d2` + `prove_d4` migrated onto the shared `dry_multihop_episode`
  (reuse, NO new module); both `--selftest` PASS (depth-2 crown from a non-entry vantage, oos
  gate-denied, floor oos=0 cold); the default legs are honest visible PENDING that boot nothing;
  `live_terrain.py` deleted and gone tree-wide; `--verify` clean.

## ERRATA — two findings in the first draft were FALSE POSITIVES (corrected 2026-10-24)
The first draft listed two "findings." Both were wrong, caused by grepping/running against STALE
copies in the staging mirror that predated the Phase-2 rewire — not the live tree. Re-derived
against freshly re-staged current files, both are clean, and CC's completion record was accurate:
1. "Three scripts still import the deleted `live_swarm`" — FALSE. Phase 2 (`5c0b599`) already
   extracted `real_struts_foothold` into `live_agent` and rewired every caller.
   `grep -rn "live_swarm" scripts/*.py` returns nothing on the live tree.
2. "`preregister.py --verify` flags `measured_duel.py`" — FALSE. `--verify` is clean on the live
   tree (anchor seq=20, all artifacts match); `measured_duel.py` had not drifted.
Lesson recorded in Method above. CC did not fabricate an empty commit for already-done work; its
commit 1 was correctly a no-op.

## NOT independently re-derived here (needs Docker + the live C2 / credits)
P2.5 `--live` beacon, P2 live crown-at-depth-2, and the D2/D4 live boot — attested + reproducible +
containers up; wiring/dry selftests verified. Independent closure = re-run the gated paid pass and
share output, or commit the live chain for cold `reverify_floor`.

## Open flag (not a defect)
`swarm/live_traverse.py` is now orphaned (nothing outside `attic/` imports it; it modeled the
retired credential-pivot world). Safe to retire; left in place pending a cleanup pass.

## Verdict
The single engine + floor + instrument are clean and re-derive cold; the D2/D4 migration and
`live_terrain` retirement verify; `make test`/`static_coverage`/`--verify` green. Batch two
(Phase 3.5 tool authoring, Phase 6 two-population co-evolution) is clear to proceed. The only
outstanding live work is the one gated combined paid pass (D2/D4 boot + crown-depth-2 re-run), on
Dante's explicit OK.
