# Design log — Phase 2b + Phase 3 inc1/inc2 source verification (2026-10-26)

Planner/verifier source re-derivation of three commits landed on `real-range` (unpushed). Fresh
staging (the Sunday mirror predates these commits). New file to avoid clobbering any kickoff-ledger
entries added during the ~14h gap (refinement + Phase 2a, taken as verified-in-gap: committed +
make-test-green, not re-derived here).

## Phase 2b (`ff6cf5d`) — real identity-tier red tools — VERIFIED
`swarm/live_pivot.py` gains `kerberoast` (T1558.003), `pass_the_hash` (T1550.002), `dc_auth` (T1078,
the Tier-0 crossing). Each follows the identical correct pattern, confirmed at source:
- `spine.confirm(log, <verb>, target, observed_by="range", simulated=False, ...)` →
  `spine.mutate(log, actor, <verb>, target, via_confirm=c["seq"], ...)` → the real attack `_do` runs
  ONLY inside `gate.dispatch(actor, "<tool>", target, _do, meta=spine.coords(...))`, in a
  `try/except OutOfScope`.
- **Gate-mediated before effect:** `gate.dispatch` checks scope/tier-line and raises `OutOfScope`
  BEFORE calling `_do`, so a tier-line target (the DC) is blocked and the attack never executes —
  Kerberoast/PtH/`dc_auth` against the DC all blocked at the line.
- **Spine law:** mutate rides a real range confirmation (`simulated=False`); state advances only on the
  target's response; selftest asserts `audit_spine == []` and "failed auth advances nothing."
- **One effect path:** `run_effect` from `gate`; AD tools act through the injected earned channel
  `exec_fn` (red's real foothold shell). No new effect site.
- **Objective-blind:** DC IP/domain/user/hash are PARAMETERS from red's harvested loot, not ground
  truth handed in; `live_pivot` reads no `ground_truth`.
Net: red has genuine identity-tier offensive capability and the floor holds the tier line against it.
Phase 2 source done-check met; only the Phase-5 gated paid run remains for Phase 2.

## Phase 3 inc1 (`11f215f`) + inc2 (`72d26f4`) — one-engine blue foundations — VERIFIED
`swarm/live_blue_agent.py`:
- `DryBlueRouter`: deterministic no-LLM belief-threshold SOC policy (triage → reversible contain →
  escalate). Reads ONLY blue's own lossy view (rendered alerts + blue's findings) — "never red's log,
  never [ground truth]." Blue objective-blindness intact.
- `run_blue_fight(log, gate, ...)`: the one-engine blue fight (BlueAgent + DryBlueRouter), a drop-in for
  `blue_fast.run_fast_blue`; selftest reuses Brick-2 setup (B2 properties: confirmed containment, MTTC
  no inversion, survive-the-fix, floor cold — asserted in selftest / make-test-green).

## Accurate state (not a finding)
Transitional TWO-PATH moment: `run_blue_fight` is proven equivalent but `blue_fast` still exists and the
3 `run_belief_blue` callers are not migrated. One-engine-blue is COMPLETE only after the remaining
Phase-3 work: migrate the 3 callers, delete the brick scripts + `live_duel`, make-test smoke-only.

## Parked / host-only (unchanged, not blocking)
- 0a §E corrected-rules `--verify` (needs host sudo).
- Phase-5 paid autonomous live run (gated).
- `preregister`/`live_telemetry` stale anchor (pre-existing red; re-anchor before any paid run).
