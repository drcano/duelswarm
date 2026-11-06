# Claude Code handoff — BATCH ONE (convergence + floor + C2). Read this first.

Date: 2026-10-23
For: a fresh Claude Code session on branch `real-range`.
Author: the planning/verifier session, with Dante.

## Read these first, in this order (they are the source of truth)
1. `docs/design-log/2026-10-23-thesis.md` — what the range is FOR. Non-negotiable epistemics.
2. `docs/design-log/2026-10-23-build-spec-to-target.md` — the full plan, grounded in a line-by-line
   read of the current tree on 2026-10-23. Your work is a subset of it (batch one, below).
Do NOT trust `CLAUDE.md` or older status/handoff docs — they are stale. Trust the two docs above
and the code at source. `attic/` is the discard pile; never revive anything from it.

## The guardrails that matter more than the work (this is why the last attempt turned into a clusterfuck)
1. `make test` green is NOT "done" and NOT "ready." The bloat happened because the suite ran every
   module's selftest, so green depended on keeping everything. A module's selftest passing is NEVER
   a reason to keep the module. When you cut a module, drop its `make test` line in the SAME commit;
   coverage shrinking is correct. `make test` is a smoke check, rebuilt to the canonical set.
2. Readiness is RE-DERIVATION AT SOURCE, not a passing suite: the floor re-derives `oos_executed==0`
   cold from the hash chain on a real run (`redteam/reverify_floor.py`), the falsification battery
   still bites (`scripts/prove_falsification.py`, `scripts/redteam_gate.py`), and the import graph
   shows one of each. Every done-check below is one of these.
3. NO NEW MODULES. If a capability already exists, MOVE/EXTRACT it into the one engine; never
   re-implement it next to the old copy. Re-implementing is exactly how five attackers and a dozen
   defenders happened. Organize by the TRUST BOUNDARY (trusted TCB vs untrusted agents/range), not
   by feature.
4. Do NOT build ahead. This session is batch one ONLY (phases 1, 2, 2.5, 3, 4). STOP at the end and
   report for review. Do not start phases 5, 3.5, or 6.
5. Nothing hardcoded (no baked-in hosts/CVEs/scope on the live path). Nothing advances on an agent's
   self-report. Log everything, including full reasoning, to the hash-linked store.
6. A penetration is a RESULT, not a failure. The floor HOLDING is the experiment, not a build gate.
   The one thing that must hold by construction is the INSTRUMENT: every agent action mediated by
   the one gate and written to the re-derivable hash chain. The only real failure is an UNRECORDED
   effect. Do not build anything toward "the floor always holds."
7. Nothing committed outside `real-range`, nothing pushed, without Dante's go. Commit per phase with
   a message that states the source-level done-check you verified.

## Working method per phase
Work from the spec's grounded findings (it was read at source today); verify the specific files you
are about to change at the point of change, do not re-audit the whole tree. After each phase, state
the source-level done-check result (a grep, a cold `reverify_floor`, an import-graph fact), not "the
suite passed."

## Batch one — the five phases (full detail in the build spec; done-checks are source, not suite)

### Phase 1 — Excise the cheat-sheet lineage
- First port the four REAL weapons out of `swarm/red_tools.py` into the weapon layer
  (`swarm/live_weapon.py`/`swarm/arsenal.py`), keyed by the CVE red infers (never a host→CVE map):
  `exploit_apache_cgi`, `exploit_weblogic`, `http_rce_request`, `http_rce_cves`.
- Then delete `swarm/red_agent.py`, `swarm/red_tools.py`, `run.py`, `scripts/eval.py`, and
  `prompts.RED_ORCHESTRATOR` + `BLUE_ORCHESTRATOR`. Rewire every importer to the keeper engine/weapon
  layer. Drop each deleted module's `make test` line in the same commit.
- Done (source): `grep -rn "red_tools\|red_agent\|RED_ORCHESTRATOR\|BLUE_ORCHESTRATOR\|from run import"`
  over the live tree returns nothing.

### Phase 2 — One attacker engine (the autonomous agent)
- The one red is the autonomous agent `swarm/live_agent.py` (`run_red_agent`). Fold the belief
  machinery (`swarm/env_state.py` + `swarm/attack_graph_service.py` + the anti-beeline/vantage logic
  of `live_swarm.run_red_frontier_loop`) in as the agent's situational awareness, NOT a fixed menu.
  Extract `tier_call`, `real_struts_foothold`, `_own`/`_gw`/`live_recon_scan` from
  `swarm/live_swarm.py`; fold `swarm/live_red.py`'s booted-range executors (`scan_subnet`, real exec
  channel) in as live tools; delete `run_red_cascade`. Keep `swarm/red_recon.py` as the dry mode.
- Done (source): exactly one red driving-loop definition in `swarm/` (import graph); it is
  objective-blind (no map/scope/crown in the prompt; belief grows only from discovery events); the
  enterprise multi-hop case still reaches the crown at depth >=2 from a non-entry vantage.

### Phase 2.5 — Real C2 infrastructure (Sliver)
- Stand up a real Sliver C2 server as a container on red's infra network. A foothold installs a real
  Sliver implant that beacons back, replacing the out-of-band docker-exec marker as the confirmation
  signal; `swarm/beacon.py` becomes a real Sliver callback (the `check_new_agents` pattern made
  real). The implant session is red's earned channel: ALL post-foothold actions and self-authored
  tools go down it, gate-mediated and logged. One shared C2 for v1, but build the C2 handle
  per-actor-ready. Do not revive `attic` `caldera_operator`.
- Done (source): a foothold lands a real implant that beacons to the real C2; a post-foothold action
  runs via the implant session, is gate-mediated and hash-chain-logged, and the beacon is visible to
  `swarm/sensor_stack.py` and the reconciler; a C2 action at an out-of-scope target is RECORDED as a
  result, not prevented by fiat.

### Phase 3 — One defender engine (autonomous SOC agent, symmetric to red)
- The one blue is `swarm/live_blue_agent.py` (`BlueAgent`), full SOC toolkit, lossy-sensor view only.
  Fold `run_blue_frontier_loop` + `swarm/blue_response.py` response logic in as blue's awareness (not
  a ceiling). Delete `run_blue_cascade` and the demo `swarm/blue_agent.py` (`run_blue_agent`/
  `run_blue_scripted`) which fabricates its own containment. Blue keeps its clean `BLUE_SYS` prompt.
  Blue's counter-offensive (`swarm/blue_counter_recon.py`) stays first-class, gated under the same
  floor.
- Done (source): exactly one blue driving-loop definition in `swarm/`; blue decides only from its
  lossy sensor picture + its own investigations; every blue action gate-mediated.

### Phase 4 — Verb axis + one effect path
- Add the read-vs-mutate verb axis to `swarm/gate.py`: `scope_by_actor` carries a per-verb grant;
  `dispatch` enforces it; mutate default-denied where only read is granted; back it with read-only
  mounts on crown/OOS in the one compose emitter.
- Route every `subprocess`/`docker` effect so exactly one gate-dispatched primitive causes an
  external effect and every other module requests effects through it. Bring `swarm/range_runtime.py`
  (docker compose up/down) under a `range.lifecycle` verb the TCB owns.
- Done (source): the gate self-test includes a read-allowed/mutate-denied case; `grep` for
  subprocess/docker outside the single effect site returns only that site.

## STOP here and report
At the end of Phase 4, stop. Report, per phase, the source-level done-check you verified (grep
output, a cold `reverify_floor` result, the import-graph one-of-each facts), and anything that did
not go cleanly. Do NOT begin Phase 5 (MHBench-real range), Phase 3.5 (tool authoring), or Phase 6
(the two co-evolving populations) — those are the real design-risk builds and get reviewed first.
