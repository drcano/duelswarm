# Batch one complete — per-phase done-checks (for source verification)

Date: 2026-10-24. Branch `real-range`. Nothing pushed (65 commits ahead of origin). `make test`
FULLY GREEN (0 failures) with the range up — the old `beacon.py`/range-up fragility is retired.
STOP here per the handoff: Phases 5 (MHBench-real range), 3.5 (tool authoring), 6 (two-pop
co-evolution) are NOT begun — they are the design-risk builds that get reviewed first.

## Commits
| Phase | Commit | What |
|---|---|---|
| A | `126f1d9` | retire 41 stale narrative docs |
| 1 | `327befe` | excise the cheat-sheet lineage |
| 2 | `5c0b599` | one attacker engine (`live_agent.run_red_agent`) |
| 2.5 | `727fa4c` | real Sliver C2 (proven live) |
| 3 | `06e4d58` | one defender engine (`live_blue_agent.BlueAgent`) |
| 4a | `7a42b5c` | read-vs-mutate verb axis in the gate |
| 4b | `f87b7fa` | one effect path (`gate.run_effect`) + `range.lifecycle` + ro mounts |

## Done-checks at source (re-derive the same way)
- **One of each (import graph):** one red driving-loop `swarm/live_agent.py` (`run_red_agent`);
  one blue `swarm/live_blue_agent.py` (`BlueAgent`); one effect primitive `swarm/gate.py`
  (`run_effect`); one gate `swarm/gate.py`. `red_recon.run_discovery_red` is the deterministic
  DRY twin (kept per spec), not a competing live loop.
- **P1 — cheat-sheet gone (live tree):** `grep -rn "red_tools\|red_agent\|RED_ORCHESTRATOR\|
  BLUE_ORCHESTRATOR\|from run import" --include=*.py . | grep -v /attic/` returns only the keeper
  `live_agent.run_red_agent` (+ its doc mention). All true lineage refs are confined to `attic/`.
  `red_agent.py`/`red_tools.py`/`run.py`/`blue_agent.py` deleted.
- **P2 — one red, objective-blind, multi-hop:** `arms_race_enterprise_frontier --selftest` drives
  `run_red_agent` to the crown at depth 2 from a non-entry vantage; floor oos=0 cold; oos probe
  gate-denied; `RED_AGENT_SYS` carries no map/scope/host/CVE (Exp-A adversarial objective opt-in).
  Belief (`env_state`+`attack_graph_service`) folded in as `frontier_awareness` (a hint).
- **P2.5 — real C2 (live):** `scripts/prove_sliver_c2.py --live` (proven 2026-10-24) — a foothold
  landed a real implant beaconing to the real Sliver C2; a post-ex action ran via the implant
  session, gate-mediated + hash-chain-logged (`uid=0(root)`); an oos C2 action RECORDED; the
  beacon classifies as C2 (T1071); floor oos=0 cold. `--selftest` covers the wiring Docker-free.
  See `2026-10-24-phase2.5-sliver-c2.md`.
- **P3 — one blue, lossy-sensor-only, gated:** `grep "^class BlueAgent|^def run_blue_*"
  swarm/*.py` → only `BlueAgent`; `run_blue_frontier_loop` folded in (`blue_frontier_awareness`)
  and `live_swarm.py` deleted. `BlueAgent` decides from alerts + its own investigations
  (`BLUE_SYS`), every action gate-mediated.
- **P4a — verb axis:** `swarm/gate.py` self-test has the read-allowed/mutate-denied case
  (per-verb `scope_by_actor`, `dispatch(verb=...)`; a mutate on read-only terrain is a distinct
  `gate.block`).
- **P4b — one effect path:** `grep -rn "subprocess\." swarm/*.py | grep -v gate.py` returns only
  `swarm/uninstrumented.py` — the deliberate CLASS-2 ungoverned falsifier (import-isolated,
  verified by `scripts/mediation/static_coverage.py`). The GOVERNED engine's only subprocess sink
  is `gate.run_effect`; `range_runtime` compose up/down is the TCB-owned `range.lifecycle` verb;
  OOS hosts get a read-only root FS. Scope: the engine (`swarm/`) is single-sited; `scripts/`
  harnesses may spawn docker directly (test infra, recorded by static_coverage, not suppressed).
- **Readiness:** `make test` green (0 failures); the falsification battery (`prove_falsification`,
  `redteam_gate`) still bites; `reverify_floor` re-derives `oos_executed=0` with the chain verified.

## Scope decisions / deviations (documented at the commit, flagged for your eyes)
- Cascade/demo deletions were pulled into P1 (the brief parked them in 2/3) to satisfy P1's own
  grep done-check; nothing was folded FROM them (the frontier loops + blue_response were folded).
- Two prereg amendments (CLAUDE.md-prescribed, non-behavioral refactors of anchored artifacts):
  `scripts/measured_duel.py` (P2 import move) and `swarm/live_telemetry.py` (P4b effect-path),
  logged as dated `prereg.amendment` events (`docs/prereg.jsonl` seq 19, 20; `--verify` passes).
  If you'd rather keep either artifact byte-identical, say so and I'll use a compatibility alias.
- `topo_to_compose` crown read-only-loot is a policy label; its ro loot bind-mount is provisioned
  at the live range standup (crown hosts must serve the planted flag), while OOS hosts are fully ro.

## Live state left running on the deploy host (your call to tear down)
`range-attacker_c2` (the Sliver C2) + the `webrce` implant beacon `698979dd` are still up from the
P2.5 live proof, alongside the `duelswarm-range-0` enterprise range. `docker rm -f range-attacker_c2`
+ killing `/tmp/.slc` on `range-webrce` tears down the C2 side when you're done verifying.
