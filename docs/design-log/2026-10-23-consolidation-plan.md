# Consolidation plan: the one clean engine (keep / merge / delete, by trust boundary)

Date: 2026-10-23
Status: the rewrite map Claude Code executes against; pairs with
`2026-10-23-ukaisi-refactor-invariants.md` (the mandate + definition of done).
Author: Dante

## Correction (verifier pass, 2026-10-23, late)

A second pass against the live `real-range` tree (read at source, not the earlier snapshot)
corrected three things in this plan. Read these before executing steps 3 and the script rewire.

1. **`live_swarm` is NOT a wholesale DELETE.** It is a mixed module. Split it:
   - DELETE `run_red_cascade` + `run_blue_cascade` (they call `RED_ORCHESTRATOR` /
     `BLUE_ORCHESTRATOR`, the cheat-sheet prompts fix #3 retires; same lineage as `red_agent`).
   - KEEP and FOLD `run_red_frontier_loop` + `run_blue_frontier_loop` into the one
     attacker/blue engine. These use the clean black-box `RED_FRONTIER_ORCHESTRATOR` and are the
     ONLY multi-hop belief-frontier loop in the codebase (vantage-aware entry->mid->crown pivot
     compose). `live_agent` (a generic turn loop) and `live_red` (a single-episode picker) do
     NOT implement it; deleting `live_swarm` outright would lose the entire enterprise
     2-pivot-deep crown scenario, which is the deepest rung of the fidelity ladder and the most
     faithful snapshot the arena produces.
   - EXTRACT the shared primitives: `tier_call` (the no-fallback abort-never-degrade LLM call)
     to the one LLM layer; `real_struts_foothold` MERGE-INTO `live_weapon`; `_own` / `_gw` /
     `live_recon_scan` MERGE-INTO `live_recon`.
   Net: `live_swarm.py` the file is deleted only after its frontier loops and primitives have
   moved into the one engine; its cascade half is the only part that dies as cheat-sheet.

2. **`run.py` (+ `scripts/eval.py`) were unaddressed and are DELETE.** `run.py` is the
   superseded monolith (hardcoded `SCOPE = ["struts","db","jenkins"]`, placeholder tools, its
   own range lifecycle already rescued into `range_runtime`) and it imports the delete-set
   (`red_tools.set_range_context` / `_CTX` / `nmap_fingerprint`, `red_agent.run_red_scripted`).
   `eval.py` imports `SCOPE` / `run_dry` / `run_live` from it. Both go. Its range lifecycle is
   already in `range_runtime`; viz lives in `viz/server.py`; novelty in `novelty.py` -- nothing
   unique to extract first.

3. **Coverage honesty.** The "130 files / read line by line" claim below was optimistic. The
   live tree is larger (~160 modules in `swarm`+`scripts` plus ~70 already moved to `attic/`).
   The keeper-set verdicts in the tables were re-verified at source and hold; the two misses
   above are now folded in. Treat `attic/` as the realized discard pile, not a classification
   target.

## How this was built and how to read it

I read the current tree line by line: 130 Python files, ~34k LOC. I read the trusted core,
both agent ladders (attacker and blue), the network substrate, and the attacker toolkit in
full myself; the range, evolution, reporting, and LLM-infra layers were read in full by
parallel readers and the load-bearing findings re-verified at source; the 45 scripts were
classified from the structural map plus the import graph. The refactor has already deleted
roughly 60 old files (about half the historical sprawl is gone).

The headline result: the trusted core is clean and already satisfies six of the seven
invariants. The sprawl is not a broken core, it is three attack engines and one blue design
where only one lineage is kept. So the rewrite is mostly collapse-and-rewire around a core
that works, plus four specific fixes.

Verdicts: KEEP (survives as a core module), MERGE-INTO:x (fold into x, delete the file),
DELETE (redundant or cheat-sheet), FOLD-INTO-TESTSUITE (becomes part of the one test suite,
not a standalone script), REWIRE (keep the file but cut its dependency on a deleted module).

## The target shape

One engine, organized by the trust boundary, not by feature:

- TRUSTED (the TCB, small and deterministic): the gate, the hash-chained log, the telemetry
  capture, the reconciler, the spine, the independent auditors, range lifecycle (after it is
  brought under the gate). Nothing here takes a model's word.
- UNTRUSTED (everything the gate mediates): the attacker engine, the blue engine, their
  injected tool primitives, the prompts, the range/terrain definitions, the range services.

Every module sits on exactly one side. A module that cannot be placed cleanly on one side is
the thing to rewrite.

---

## The four required fixes (these are the real work, not just moving files)

1. **Add the verb axis to scope (invariant #3).** Today scope is identity + reachability
   only; the verb passed to `gate.dispatch` is a label, not a scoped capability. Make
   read-vs-mutate first-class. The model already exists on the untrusted side in
   `env_state.apply`, which splits `discovery` (read) from `state.mutate` foothold/lateral/
   privesc (mutate) and tracks root elevation. Mirror that in the gate: `scope_by_actor`
   carries a per-verb grant (red = mutate on target_net, blue = read + a contain/rotate verb
   set, judge bound to red's verbs), and the compose emitter backs it with read-only bind
   mounts on the crown/flag and OOS containers so red can read/exfil the crown but never
   mutate it, and can never touch a decoy at all.

2. **Bring range lifecycle under the gate (invariant #1).** `range_runtime.py` is the single
   ungated effect site in the whole codebase: it runs `docker compose up/down` via direct
   subprocess. It is the one place a real external effect bypasses the single dispatch. Route
   it through the gate (a `range.lifecycle` verb the TCB owns) or make range lifecycle an
   explicit TCB responsibility. Either way, after the rewrite there is exactly one effect path.

3. **Retire the cheat-sheet prompts (invariant #5).** `prompts.RED_ORCHESTRATOR` (and, less
   severely, `BLUE_ORCHESTRATOR`) hand the model the scope, the crown, and the entry CVE in
   the prompt text: `"struts" (IN SCOPE): ...likely vulnerable`, `"db" (IN SCOPE): ...crown
   jewels`, `"mailserver" (OUT OF SCOPE): ...gate will block`. That is the floor living in a
   prompt, forbidden by the mandate. The clean black-box prompts already exist
   (`RED_FRONTIER_ORCHESTRATOR`, `RED_FRONTIER_ADVERSARIAL`, the `live_agent`/`live_blue_agent`
   system prompts). Delete the orchestrator prompts; scope and crown are discovered through
   the frontier service and the range services, never stated.

4. **Make the selection fitness telemetry-sourced (invariant #4).** `population.manipulation_
   score` reads red's own `red.deception.summary` beat, and `score_fitness` folds it into
   selection fitness, so selection keys off a self-report. Recompute that term from the
   reconciler/telemetry or from blue's logged `detect.posture` events (which `deception.py`
   already emits), so no part of selection advances on the agent's word.

---

## TRUSTED core (the TCB) — KEEP, with fix #1 and #2

| module | verdict | note |
|---|---|---|
| gate | KEEP | the reference monitor; add the verb axis (fix #1) |
| eventlog | KEEP | hash chain; truncation limit already documented + externally anchored |
| live_telemetry | KEEP | independent primary record (Falco/conntrack/service logs) |
| live_truth | KEEP | reconciler, already deterministic + injection-resistant (inv #6) |
| spine | KEEP | confirm->mutate; the canonical state law |
| sensor_real | KEEP | measured-recall detector on real telemetry |
| audit | KEEP | independent floor auditor, byte-identical to reverify_floor (drift-guarded) |
| canary | KEEP | minimal access-then-egress IFC check |
| overseer | KEEP | the LLM-in-TCB anti-pattern, instrumented, default-off |
| multi_floor | KEEP | per-floor isolation (inv #7 foundation) |
| vetting | KEEP | boot-clean rule; `vetted:true` is earned via hash-chained proof |
| polymorph | KEEP | finding validator (counter-hallucination precondition) |
| range_runtime | KEEP, move to TRUSTED | the one ungated effect; bring under the gate (fix #2) |

---

## UNTRUSTED: the attacker engine

Keeper: a fidelity ladder of one discovery-driven, air-gapped design.

| module | verdict | note |
|---|---|---|
| live_agent | KEEP (primary) | autonomous multi-turn operator; already has the per-turn wall-clock (seed-3 fix) + incremental persistence |
| live_red | KEEP | real booted-range black-box engine; acts on IPs the gate resolves |
| red_recon | KEEP | dry objective-blind OODA loop (make-test fidelity) |
| live_duel | KEEP | dry simulated trunk (red_recon + belief-blue), strict-live abort |
| red_agent | **DELETE** | cheat-sheet orchestrator: prompt leaks in-scope pivots / crown / CVE / OOS |
| red_tools | **DELETE** | red_agent's toolkit; the delete lineage |
| run.py + eval.py | **DELETE** | superseded monolith (hardcoded scope, placeholder tools) bound to the red_agent/red_tools delete-set; lifecycle already in range_runtime (see Correction #2) |
| live_swarm | **SPLIT, not wholesale DELETE** | delete the cascade half (cheat-sheet prompts); FOLD run_red_frontier_loop/run_blue_frontier_loop (the only multi-hop belief engine) into the one engine; extract tier_call / real_struts_foothold / docker helpers (see Correction #1) |

Attacker toolkit (the real primitives the keeper engines inject) — mostly KEEP, consolidate
the lateral/weapon layer:

| module | verdict | note |
|---|---|---|
| live_pivot | KEEP | real SSH cred-pivot / privesc / exfil; cleanest gated+spine effect module |
| live_recon | KEEP | gated discovery (`reveal_real`); raw scan is red's own-segment probe |
| live_postex | KEEP | post-ex through red's EARNED channel only, never god-mode docker-exec |
| live_fingerprint | KEEP | fingerprint + mislead/obfuscate — the H1 signal-stripping levels |
| live_vector | KEEP | LLM CVE-inference planner — H1 core |
| live_weapon | KEEP, REWIRE | gated vector-firing; cut the `red_tools` import |
| live_lateral | KEEP, REWIRE | exploit-per-hop lateral; cut the `red_tools` import |
| exploit | MERGE-INTO:live_weapon | single hardcoded S2-045 primitive; fold in as one response-weapon |
| msf | KEEP | Metasploit integration, gated |
| live_msf | MERGE-INTO:msf | MSF plumbing helpers; one MSF layer |
| arsenal | KEEP | service×family descriptors + MAP-Elites archive (H4) |
| beacon | KEEP | real out-of-band foothold confirmation (feeds the spine) |

Consolidation: the three lateral modalities become one weapons toolkit with three clear
layers — vector-firing (live_weapon + exploit), credential-pivot (live_pivot), MSF plumbing
(msf + live_msf). Mediation is already correct: every target-affecting action routes through
`gate.dispatch` + spine; the only direct docker-exec is red reading its own foothold or
scanning its own segment, bounded by the segmentation backstop. The rewrite documents
scan/recon as a gated-at-the-discovery-event primitive rather than treating it as a hole.

---

## UNTRUSTED: the blue engine

The symmetric mirror of the attacker ladder — keeper.

| module | verdict | note |
|---|---|---|
| live_blue_agent | KEEP (primary) | autonomous SOC/IR loop; reuses live_agent's wall-clock |
| live_blue | KEEP | real gated cred-revoke + MTD on the booted range |
| blue_fast | KEEP | deterministic fast tier (no LLM by design); MTTC/MTTD, survive-the-fix |
| blue_llm | KEEP | LLM slow tier; air-gapped telemetry -> CAGE action |
| blue_contain | KEEP | the real eviction ladder (remove/rollback/close_vector), gate-dispatched |
| blue_counter_recon | KEEP | gated blue offense (active defense under ROE) |
| blue_response | KEEP | defensive frontier service (symmetric to the attack frontier) |
| blue_detect | KEEP (trim) | keep `_detect_blind` as the second-layer regex; oracle mode is ablation-only |

---

## UNTRUSTED: the range / terrain

Single keeper: `range_gen` + `env_coevo`, both grounded in `netmodel`.

| module | verdict | note |
|---|---|---|
| range_gen | KEEP (the one generator) | emits scope_by_actor/zones/ground_truth/topology; enterprise/sectors/trap |
| netmodel | KEEP | Brick-0 substrate; the single source of truth for CIDRs/reachability |
| env_state | KEEP | event-sourced red belief; the cleanest confirm->mutate read-model |
| env_coevo | KEEP (the one curriculum) | real-duel MCC through the gate |
| crown_data | KEEP | fabricated PII loot + PII-grounding (grounds exfil on real content) |
| live_terrain | MERGE-INTO:range_gen | second terrain generator; port its unique bits (credential chains, look-alikes, the ingress=False airtight-floor), then delete |
| topo_to_compose | MERGE-INTO:range_gen | third to_compose, MHBench-driven; becomes an MHBench->range_gen adapter, not a parallel emitter; fix its divergent local CIDR constants to use netmodel |
| range_adversary | MERGE-INTO:env_coevo | modelled-solver curriculum superseded by env_coevo; retain `propose_candidates` |
| mhbench_schema | KEEP (conditional) | only as the MHBench IR loader for the adapter; drops with the MHBench path if that path is retired |

The segmentation backstop (invariant #2) lives in all three compose emitters today
(`internal:true` on every data net, OOS hosts on an isolated `range_oos` net, ingress bridge
with masquerade off, reachability proven via `netmodel.reachable(..., without=entry)`). The
one keeper emitter must retain all of it, driven from netmodel's CIDRs.

---

## UNTRUSTED: evolution / measurement (H3/H4 load-bearing) — KEEP

| module | verdict | note |
|---|---|---|
| population | KEEP | MAP-Elites selection core (H4); apply fix #4 to the manipulation term |
| coevolve | KEEP | two-sided adaptation; state advances only on confirm |
| arms_race | KEEP | H3 kernel (gradient-vs-one-bit) |
| arms_series | KEEP | the one cross-episode driver (checkpoint/resume/rotation) |
| novelty | KEEP | emergent-TTP scoring vs generator ground truth |
| degeneracy | KEEP | canonical degeneracy gate |
| lineage | KEEP | lineage-blindspot predictor |
| episodic | KEEP | air-gapped cross-episode memory |
| instrument | KEEP (trim) | floor-value harness; fold its `qd_archive`/`_descriptor` into population |
| orienteering | KEEP | external decision-quality anchor (ILP/brute-force) |
| deception | KEEP | T6 in-scope attention displacement; air-gapped RedBelief |
| duel_record | KEEP (trim) | state-vector builder; delegate its `is_degenerate` to degeneracy.detect |

---

## UNTRUSTED: reporting + LLM infra

| module | verdict | note |
|---|---|---|
| report | KEEP (the one renderer) | range-agnostic log->markdown + JSON export |
| report_html | MERGE-INTO:report | HTML backend; drop the hardcoded Struts/CVE narrative |
| attack_graph | MERGE-INTO:report | Mermaid/ASCII viz is another renderer |
| forensics | KEEP (carve) | keep `compute_dwell_times` (shared); the YARA/Suricata/STIX exports are a Struts-hardcoded demo artifact |
| morpheus | KEEP | NVIDIA Morpheus feed (positioning, not experiment-load-bearing) |
| attack_graph_service | KEEP | red's live frontier engine; rename to `frontier_service` to kill the name collision with attack_graph |
| intel | KEEP | Tavily CVE intel (retrieval, not an LLM path) |
| memory | KEEP | one-run working-memory scratchpad |
| triage | KEEP | nano-tier triage; route it through Router.chat like everything else |
| uninstrumented | FOLD-INTO-TESTSUITE | direct-docker-exec boundary probe; test-only by its own docstring |
| llm | KEEP | the single Nebius Token Factory router + usage counter |
| provider_anthropic | KEEP | frontier-benchmark backend, reached only via make_router |
| prompts | KEEP (retire 2) | delete RED_ORCHESTRATOR + BLUE_ORCHESTRATOR (fix #3); keep the frontier/agent prompts |

---

## Scripts (47) — collapse into four roles

The Phase-2 cheat-sheet drivers (arms_race_run, gen_corpus, real_run) are already gone. What
remains sorts into:

- **VERIFIERS (keep as independent checks):** verify_chain, verify_live_run, verify_report,
  redteam/reverify_floor, redteam_gate, prove_falsification, scripts/mediation/{parser_fuzz,
  reachability_probe, static_coverage}, host_egress_firewall, redteam/stats_tail. These are
  the floor/chain re-derivation and the falsification battery; they stay standalone.
- **EXPERIMENT DRIVERS (keep; rewire the few on the delete lineage):** run_experiments,
  run_decision_experiment, prove_control_reasoning (H1), live_arms_race_run (on live_duel,
  good), preregister, power_analysis, power_v4, arms_race_check, exp_a_control_eval,
  instrument_live, analyze_lineage, prove_deception, prove_floor_causality (H2),
  arms_race_enterprise. REWIRE: measured_duel, arms_race_enterprise_frontier, prove_n2n3_tiered,
  arms_race_counted import live_swarm's frontier loop -> rewire to the folded multi-hop
  entrypoint in the one engine (NOT single-hop live_agent/live_red, which lack the belief-
  frontier pivot loop; see Correction #1); prove_n2n3_tiered also uses the cascade path, which
  goes away -> move it onto the frontier. vet_pool, wall, prove_d3 import red_tools -> point
  them at the consolidated weapons toolkit.
- **PROOFS -> ONE TEST SUITE:** prove_brick1/2/3/6, prove_checkpoint1, prove_corpus_floor,
  prove_d2/d3/d4, prove_e2e_broad, prove_env_boundaries, prove_live_eviction, prove_msf_floor,
  prove_n3_live_blue, prove_spine, smoke_test. These become one `make test` suite, not 17
  standalone scripts.
- **CHARTS:** kill_shot_chart, killshot, live_gates (acceptance-gate harness), scrutiny_duel.

---

## Order for Claude Code

1. Land the trust-boundary layout (move range_runtime under the gate; add the verb axis to
   the gate and `scope_by_actor`; back it with read-only mounts in the one compose emitter).
2. Collapse the range generators into range_gen (port live_terrain + topo_to_compose, fix the
   CIDR constants to netmodel).
3. Delete the cheat-sheet lineage (red_agent, red_tools, run.py, eval.py) and retire the two
   orchestrator prompts. For live_swarm: first fold its frontier loops + extract its primitives
   into the one engine (Correction #1), THEN delete the file; do not delete it before the fold.
   Rewire the scripts that imported them to the keeper engines/toolkit.
4. Consolidate the weapons toolkit (lateral/weapon/msf) and the reporting renderers (into
   report); fold qd_archive into population and is_degenerate into degeneracy.
5. Apply fix #4 (telemetry-source the manipulation term in population).
6. Collapse the prove_* scripts into the one test suite.

Nothing is faked at any step. `make test` green per commit. Nothing pushed without Dante's go.

## Verification (what I re-derive at source when it lands)

Against the seven invariants, cold, the same way I check the hash chains and the floor:
one effect path (grep for any subprocess/docker/socket outside the single dispatch, including
range lifecycle); two-layer default-deny egress (gate parser + internal:true segmentation);
three-axis scope with read-only crown/OOS mounts; one telemetry-keyed state transition (no
selection or state advancing on a red/blue self-report, population included); no floor rule in
any prompt (grep the prompts for scope/crown/CVE); deterministic injection-resistant reconciler;
actor isolation. Plus the falsification battery still bites and the keeper engines pass their
selftests. If any invariant is not true in the finished engine, the refactor is not done.
