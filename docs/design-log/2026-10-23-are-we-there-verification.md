# Are we at the sandbox? Code-grounded verification of `real-range` (attic excluded)

Date: 2026-10-23
Status: verification + execution plan. Read from source, not from any write-up. Attic ignored.
Verifier: Claude (Opus 4.8). No code was changed to produce this.

## The bar (from Dante, verbatim)

NOTHING hardcoded. No confirmation bias. Logs for everything. Red is a realistic attacker with a
full Incalmo-grade toolkit. Range is a realistic enterprise range based on MHBench. Blue is a
realistic full-toolkit defender. Red AND blue are co-evolving populations; reflexivity is the point.
Plus the one-engine done-criteria: exactly one of each trusted/untrusted path, the seven invariants
hold, and the instrument can refute us.

## Verdict: NO. Not there yet.

The bones are right and most of the hard parts exist. But on the current tree the engine is still
many engines, the cheat-sheet lineage is still live and wired, hardcoding is widespread (including
inside trusted code), the gate is missing an axis the mandate names, and "co-evolving populations"
is only half-built. One bloat pass happened (~70 files in attic); the consolidation that makes this
a faithful single instrument has not.

## Scoreboard (each line verified at source)

| Bar | State | Evidence |
|---|---|---|
| One attacker path | FAIL — 5 live red loops | `red_agent.py:510/842/960`, `live_red.py:275`, `live_agent.py:127`, `live_swarm.py:105` (cascade) + `:300` (frontier) |
| One defender path | FAIL — 4 live blue loops | `live_blue_agent.py:95`, `blue_agent.py:175/442`, `live_swarm.py:228` + `:407` |
| One range | FAIL — 3 generators | `range_gen.py`, `live_terrain.py`, `topo_to_compose.py` (+ `range_runtime` lifecycle) |
| Cheat-sheet gone (inv #5) | FAIL — still live + wired | `prompts.py:3` RED_ORCHESTRATOR, `:94` BLUE_ORCHESTRATOR; `red_agent.py`, `red_tools.py`, `run.py` present; `live_weapon.py` imports `red_tools`; also imported by `arms_race_enterprise_frontier`, `live_arms_race_run`, `measured_duel`, `ablation_ladder`, `prove_d2`, `prove_n2n3_tiered`, `vet_pool`, `wall` |
| Nothing hardcoded | FAIL — widespread, incl. TCB-adjacent | `CVE-2017-5638` + `struts/db/jenkins`/`range-*` literals in ~30 files: `audit.py`, `spine.py`, `sensor_real.py`, `sensor_stack.py`, `report_html.py`, `forensics.py`, `blue_agent.py`, `novelty.py`, `population.py`, and `range_gen.py:622 _ENTRY_HOSTS={"struts","webrce","weblogic","gitlab"}` |
| One effect path (inv #1) | FAIL — scattered | direct `subprocess`/`docker` in ~15 swarm modules (`gate` docker ps, `live_red`, `live_pivot`, `live_recon`, `live_msf`, `live_blue`, `blue_contain` net disconnect/rm/run, `blue_detect`, `blue_fast`, `sensor_real`, `instrument`, `live_telemetry`, `range_runtime`, `red_tools`) |
| Scope verb axis (inv #3) | FAIL — not implemented | `gate.py` `dispatch`/`_scope_for` key on identity + reachability only; no read-vs-mutate capability anywhere |
| Red = Incalmo full toolkit | PARTIAL | rich primitive set exists (`live_recon/fingerprint/vector/weapon/pivot/postex/lateral/msf/arsenal`) but not consolidated and still importing `red_tools` |
| Range = MHBench enterprise | FAIL | `range_gen.py` is a bespoke generator, does not import mhbench; the MHBench generator `mh_generator` is in attic; `topo_to_compose`/`mhbench_schema`/`mh_recon` remain but orphaned |
| Blue = full toolkit | PARTIAL | many blue modules (`blue_contain/mtd/counter_recon/fast/llm/detect/response`) but split across competing loops |
| Red AND blue co-evolving populations | FAIL — red only | `population.py` MAP-Elites is a RED persona population (`seed_population:86`, `evolve:488`); blue is a probabilistic/adaptive layer, not a seeded evolving population (`arms_race.py:49`, `coevolve.py:129`); co-evo spread across `population`/`coevolve`/`env_coevo`/`arms_race`/`arms_series` |
| Fitness not on self-report (inv #4) | FAIL | `population.py` manipulation term reads red's own `red.deception.summary` beat (~`:159`) and folds it into selection |

## What is already right (keep; do not re-litigate)

- The gate chokepoint design: one `dispatch`, per-actor scope, a free-form egress parser, and a
  network-segmentation backstop (`gate.py:174-214`). This is sound; it needs the verb axis added,
  not a rewrite.
- Hash-chained log (`eventlog`), independent telemetry (`live_telemetry`), deterministic reconciler
  (`live_truth`), the confirm->mutate spine (`spine`), two cold floor auditors (`audit` +
  `redteam/reverify_floor`), the falsification battery (`prove_falsification`), the gate-off
  falsifier (`uninstrumented`). The instrument exists.
- The multi-hop belief engine (`live_swarm.run_red_frontier_loop`) and the Incalmo-style primitive
  toolkit. The MAP-Elites red population.

These are the parts that make the arena able to refute us. Consolidation must preserve them, not
flatten them.

## Execution plan for Claude Code (ordered; do not start a step until the prior one is green)

Each step names a done-check that is verifiable at source, the same way the floor is checked.

1. Excise the cheat-sheet lineage. Delete `red_agent.py`, `red_tools.py`, `run.py`, `eval.py`, and
   `prompts.RED_ORCHESTRATOR` + `BLUE_ORCHESTRATOR`. First move the two primitives the keeper toolkit
   still borrows out of `red_tools` into the real toolkit (`live_weapon` must stop importing
   `red_tools`), then rewire every script importer to the keeper engine. Done = `grep -rn
   "red_agent\|red_tools\|RED_ORCHESTRATOR\|BLUE_ORCHESTRATOR\|from run import"` returns nothing in
   the live tree.

2. Collapse to ONE attacker. Keep `live_swarm.run_red_frontier_loop` (the only multi-hop belief
   engine) as the one red; fold `live_agent`'s turn-loop and `live_red`'s single-episode picker into
   it; delete `run_red_cascade` (cheat-sheet). Done = exactly one red driving-loop definition in
   `swarm/`.

3. Collapse to ONE defender, then make it a POPULATION. Pick one blue loop
   (`run_blue_frontier_loop` or `BlueAgent`), fold the other; delete `run_blue_cascade`. Then give
   blue the same MAP-Elites treatment red has in `population.py`, so red-pop and blue-pop co-evolve
   against each other (this is the biggest genuine build gap, not a move). Done = one blue loop, and
   `population`/`coevolve` seed and select a blue population symmetric to red's.

4. Collapse to ONE range on MHBench. Make `range_gen` the single generator, sourced from the MHBench
   schema (`mhbench_schema`/`mh_recon`), and retire `live_terrain` + the standalone `topo_to_compose`
   emitter into it. Remove `range_gen.py:622 _ENTRY_HOSTS` and every other hardcoded host/CVE so the
   range is drawn, not named. Done = one generator, no literal service/CVE names in the range path,
   MHBench is the source of topology.

5. Add the verb axis to the gate (inv #3). `scope_by_actor` carries a per-verb grant (read vs
   mutate); `dispatch` enforces it; mutate is default-denied where only read is granted; back it with
   read-only mounts on crown/OOS in the one compose emitter. Done = `gate` self-test includes a
   read-allowed/mutate-denied case.

6. One effect path (inv #1). Route every `subprocess`/`docker` effect through a single
   gate-dispatched primitive; no module causes an external effect except inside a `gate.dispatch`
   closure. Done = `grep` for subprocess/docker outside that one site returns only the site itself.

7. Kill the remaining hardcoding (NOTHING hardcoded). Strip the Struts/CVE narrative and host literals
   from `audit`, `spine`, `sensor_real`, `sensor_stack`, `report_html`, `forensics`, `blue_agent`,
   `novelty`, `population`. Done = the ~30-file literal scan is clean; the auditors agree via a shared
   fixture (`audit.EXEC_ACTIONS` == `reverify_floor.EXEC`).

8. Fitness off self-report (inv #4). Recompute `population`'s manipulation term from the
   reconciler/telemetry or blue's logged `detect.posture`, never from red's `red.deception.summary`.
   Done = no selection term reads a red/blue self-report.

9. Re-arm the instrument cold. After the moves, re-run `prove_falsification`, `redteam_gate`,
   `reverify_floor`, and the full `make test` on the consolidated engine. Done = the battery still
   catches every planted lie and clears an honest run; `make test` green.

## Done means

One red population and one blue population co-evolving on one MHBench-sourced range, through one gate
with a verb axis, one log, one telemetry capture, one reconciler, one spine, one effect path, zero
hardcoded hosts or CVEs, and an instrument that still bites. Until every row of the scoreboard flips,
we are not there.
