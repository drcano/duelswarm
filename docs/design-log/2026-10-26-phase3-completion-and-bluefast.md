# Design log — Phase 3 completion verified + the blue_fast decision (2026-10-26)

Fresh source re-derivation (mirror cleared first; an earlier pass of mine mis-read a STALE stage and
wrongly claimed a legacy blue path still existed — corrected here at source).

## Phase 3 blue consolidation — COMPLETE, verified fresh
Arc: `11f215f` (DryBlueRouter) → `72d26f4` (fight on BlueAgent) → `d4e01ee` (retire run_belief_blue) →
`6450ed9` (brick scripts) → `3a1cd69` (delete live_duel).
- `swarm/live_duel.py` DELETED (absent from the tree). Zero dangling `live_duel` refs (prose history only).
- `run_belief_blue` retired: zero import/call references (docstring history only).
- The 3 duel callers AND the paid-run script are all on the one engine:
  `verify_live_run` / `scrutiny_duel` / `instrument_live` import `run_discovery_duel` from `swarm.live_red`
  (re-homed there from the deleted live_duel), and `run_discovery_duel` calls
  `from swarm.live_blue_agent import run_blue_fight` → `run_blue_fight(...)`. `scripts/live_arms_race_run.py`
  (the Phase-5 PAID run; NOT exercised by `make test`) was re-checked FRESH: line 45 is now
  `from swarm.live_blue_agent import run_blue_fight` (old `from swarm.live_duel import run_belief_blue`
  gone), calls at 191/237. So the paid run scores off the verified Phase-4 one-engine blue.
Phase 5's blue side is unblocked and on the one engine.

## Correction to CC's framing — blue_fast is NOT purely a utility layer (found same pass)
True: `run_blue_fight` imports the shared utilities from `blue_fast` (`detect_kill_chain`, `_sim_contain`,
`mttc_mttd`, `survive_the_fix`, `compare_detectors`). BUT `run_fast_blue` — a full second blue FIGHT, not
a utility — is still LIVE, called by `env_coevo.py:63` and `instrument.py:48` (and `blue_fast`'s own
selftest). So the duel/paid path is one-engine, but two non-duel paths still run the old fast fight.

## Decision (per the mandate: no bloat, no parallel universes, one clean engine)
`run_fast_blue` is a full second blue FIGHT in active use (`env_coevo` + `instrument.py`) — a parallel
universe. It is collapsed NOW, before the demo, not deferred. (An earlier draft of this entry called it
an optional post-demo tidy; that let the deadline soften a hard rail and was wrong — corrected.)
- DELETE `run_fast_blue`. Repoint `env_coevo.py` and `instrument.py` to `run_blue_fight` with the dry
  router (already deterministic + no-LLM, so no capability is lost — which is exactly why a second
  implementation has no reason to exist).
- `blue_fast` keeps ONLY the single-source utilities the one engine imports (`detect_kill_chain`,
  `_sim_contain`, `mttc_mttd`, `survive_the_fix`, `compare_detectors`). One implementation imported once
  is not a parallel universe or bloat; the module name is cosmetic (fold into the engine's module if
  preferred). The mandate point: the second FIGHT dies, one engine runs blue everywhere.
- Verify after: zero `run_fast_blue` refs in a FRESH tree grep; `env_coevo`/`instrument` genuinely on
  `run_blue_fight` with return-shape/behavior preserved; floor cold; make test green.

## Verification scope note
Verified fresh: the 3 callers, the paid-run script, `live_red.run_discovery_duel`, `live_blue_agent`,
`blue_fast`, `env_coevo`, `instrument`. Tree-wide "zero dangling live_duel/run_belief_blue" beyond this
set rests on make-test-green (a deleted-symbol import crashes collection) plus the fresh check of the one
make-test-exempt script (the paid run). Parked/host-only unchanged: §E `--verify`, preregister re-anchor,
Phase-5 range boot + offensive-tool confirmation.
