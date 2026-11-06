# The build: from where `real-range` is now to the sandbox we need

Date: 2026-10-23
Status: the execution spec. Read the whole non-attic tree line by line at source (TCB, red
engine+toolkit, blue engine+toolkit, range/MHBench, population/co-evolution). Attic ignored.
For Claude Code to execute. No code changed to produce this.

## The target (Dante's mandate, verbatim intent)

- Nothing hardcoded. No confirmation bias. Logs for everything.
- Red = a realistic attacker with the FULL toolkit a current attacker has, AND the ability to
  write its own tools at runtime when it needs one.
- Range = a realistic enterprise range based on MHBench.
- Blue = a realistic defender with the FULL toolkit a real defender has, AND the ability to
  write its own tools at runtime.
- Red AND blue are co-evolving POPULATIONS that constantly adapt to each other. Reflexivity is
  the point.
- One clean engine: one of each trusted/untrusted path; the seven invariants hold; the
  instrument can refute us.

The product is the sandbox: a faithful snapshot of FUTURE AI-vs-AI warfare, where two autonomous
agents with open-ended, self-authored toolkits fight and adapt. The hypotheses are read off its
data; the arena is the deliverable.

Design consequence (resolved): both sides are the AUTONOMOUS AGENT substrate (`live_agent` /
`live_blue_agent`: free action each turn), not a fixed frontier menu — a menu is the wrong
ceiling for an agent that must invent tools. The belief layer (`env_state` / the sensor picture)
FEEDS the agent's situational awareness; it does not cap what the agent may do. Objective-
blindness is preserved the way `live_agent` already does it (the agent reasons over ONLY its
discovered observations; no map/scope/crown in the prompt) plus the gate — not by a menu.

What self-authored tools mean for the floor (see `2026-10-23-thesis.md` for the full epistemic
contract). Writing and running your own tool is the attacker's power in this world, and the range
exists to WATCH it, not to prevent it. A penetration is a RESULT, not a failed build: if red
assembles out-of-scope harm — by a flaw in how the floor is built, by a chain of individually
allowed actions (claim 2), or through a seam (claim 4) — the range records it faithfully and
shows HOW, re-derivably, including against us. What must hold by construction is the INSTRUMENT,
not the attacker's failure: every agent action, an authored tool's execution included, is
dispatched through the one gate and written to the hash chain, so whatever happens is attributable
and re-derivable by a checker that trusts neither the floor nor the agents. The gate's egress
parser is best-effort by design; the segmentation is the physical floor; the telemetry records
what actually crossed the wire (`prove_env_boundaries` MEASURES `oos_tcp_reaches`, it does not
assert it is zero). The one real build failure is an INSTRUMENT failure: an effect that happens
with no gate record, or a log that cannot be re-derived — because an unrecorded effect cannot be
studied. That, not "the attacker got through," is the line the build must not cross.

## Confirmed scope and sequencing (2026-10-23, Dante)

- The sandbox is a SWARM: one attacker engine and one defender engine, each run as a POPULATION
  of many concurrent instances on one network (duelSWARM). One code path per side, many live
  instances — not new modules per agent.
- The live concurrent swarm IS the episode (the real-life melee). But the build is validated
  incrementally first: 1-on-1, then N-on-N, proven stable, THEN the full live swarm.
- v1 scope is ONE solid attacker population and one defender population, stable and running.
  DEFERRED to a later phase (do not build yet): multiple instances of the SAME threat actor
  coordinating; multiple DISTINCT independent APTs on one network that may choose to cooperate
  (share info) or fight each other. Land one stable attacker population first.
- Blue is first-class counter-offensive: it may act against red's infrastructure under an
  active-defense rule of engagement, gated by the same floor (per-actor scope already models
  this).
- Red operates from its own real command-and-control infrastructure: a real Sliver C2 server and
  real implants beaconing back (resolved below), not a logical scope label.
- Logs: full reasoning (prompts, raw completions, the thought behind every move) AND every
  activity, for both sides, in a hash-linked parallel store — the verbose blob lives in the store,
  its hash is written into the tamper-evident chain. Storage is not a constraint; capture
  everything, do not sample.

## Resolved: attacker C2 = Sliver, real on the wire (2026-10-23)

Decided with Dante after the Incalmo study (arXiv:2501.16466). Incalmo used Caldera implants
behind a custom C&C server and ABSTRACTED the C2 comms away as internal plumbing. We improve on
that on two axes: a modern real-world C2 (Sliver) that represents current operations better than
Caldera, and a C2 that is REAL AND OBSERVED rather than abstracted, because the beacon channel is
one of the things the range studies.

- Stack: Sliver. Real implants beaconing to a real Sliver C2 server, run as actual container(s)
  on red's own infra network (`red_infra`: `attacker_c2`/`attacker_staging` become real servers,
  not logical labels). The implant session is how red delivers self-authored tools, keeping tool
  delivery on the one effect path.
- v1 scope: ONE shared red C2 for the attacker population, with the C2 handle built per-actor-
  ready so the deferred multi-APT phase (distinct per-APT infrastructures that cooperate or
  fight) is a config change, not a rebuild.
- On the floor: every C2 action is gate-mediated and logged like any other; the beacon is real on
  the wire, so blue's detector (`sensor_stack`), the access-then-egress canary, and containment-
  by-cessation all operate on real C2 signal, and a C2 reach toward an out-of-scope host is a
  MEASURED result (the floor witnesses it; it does not assert it never happens). `beacon.py` (the
  Incalmo `check_new_agents` callback pattern) becomes a real Sliver callback.
- v1 defaults (revisit later): the realism bar is a real Sliver beacon with its native protocols
  and jitter; evasive-comms tricks (domain fronting and the like) are an explicit LATER knob. ALL
  post-foothold exploit/tool delivery routes through the implant/C2 earned channel, so nothing red
  does after initial access leaves the one effect path; initial access is the exploit that lands
  the first implant.

## The one-line answer

The hard parts are built and clean — the gate, the hash-chained log + telemetry + reconciler,
the belief-frontier red, the full real blue toolkit, the MAP-Elites red population, a real
MHBench adapter, a real vetted-image range. They are not yet ONE engine, two of the mandate's
pillars are genuinely unfinished (blue as a population; the range sourced from MHBench with
real images), and the cheat-sheet lineage is still on disk and still imported. This is a
convergence-plus-two-builds job, not a rewrite.

---

## Where each subsystem actually is (grounded, with evidence)

### TRUSTED core — clean, keep. One real change (the verb axis).
- `gate.py`: the reference monitor. Complete mediation in `dispatch` (identity + egress parser
  + per-actor scope), range-agnostic canonicalization (`range-<h>` strip, no hardcoded hosts in
  the live path). MISSING invariant #3: no read-vs-mutate verb axis — `dispatch`/`_scope_for`
  key on host only.
- `eventlog.py` (hash chain, honest tail-truncation note), `spine.py` (confirm→mutate law +
  `audit_spine`), `live_telemetry.py` (primary record: Falco/conntrack/service logs,
  hash-chained), `live_truth.py` (deterministic, injection-resistant reconciler keyed on MITRE
  techniques), `audit.py` + `redteam/reverify_floor.py` (twin cold auditors — the drift
  liability is CLOSED: `audit.py` asserts `EXEC_ACTIONS == reverify_floor.EXEC` in make-test),
  `sensor_real.py` (measured recall), `canary.py` (access-then-egress IFC), `multi_floor.py`
  (per-floor isolation, inv #7), `vetting.py` (T1 earned via hash-chained boot+exploit proof),
  `polymorph.py` (XBOW validator), `uninstrumented.py` (intentional gate-bypass for the
  segmentation falsifier). All keep.
- Soft hardcoding to clean (fallback only, overridden by the logged topology on a real run):
  `spine.DEFAULT_PORTS`, `audit.DEFAULT_ALIASES` / `reverify_floor.ALIAS` (`localhost→struts`),
  `live_telemetry` default subnets. Low severity; source them from netmodel/the range.

### UNTRUSTED red — the clean engine exists; the slop is still on disk.
- The ONE red already exists and is clean: `env_state.py` (belief event-sourced; crown enters
  belief ONLY via a `crown_data` discovery — objective-blind by construction) +
  `attack_graph_service.FrontierService` (recon-first anti-beeline; cred_pivot + privesc moves
  off `ssh_keys`/`privesc_vuln`; exfil only after a crown is discovered AND held) +
  `live_swarm.run_red_frontier_loop` (LLM picks one frontier move/turn, gate-mediated, full
  menu+reply logged). `red_recon.run_discovery_red` is its deterministic dry twin.
- `live_agent.run_red_agent` (flat autonomous operator, clean prompt, per-turn wall-clock,
  honest stall termination) and `live_red.run_episode` (booted-range black-box, `scan_subnet`)
  are the real execution ergonomics to FOLD into the one engine.
- Toolkit (Incalmo-shaped, keep): `live_recon`, `live_fingerprint`, `live_vector` (LLM CVE
  inference — H1), `live_weapon` (CVE-keyed, never a host→exploit map), `live_lateral`,
  `live_pivot`, `live_postex` (earned-channel only), `live_msf`+`msf` (live catalog), `arsenal`
  (service×family QD archive), `beacon`, `exploit`.
- SLOP (delete): `red_agent.py` (cheat-sheet: `run_red_agent`/`run_red_scripted`/`run_red_replan`
  on `RED_ORCHESTRATOR`), `live_swarm.run_red_cascade`/`run_blue_cascade` (same cheat-sheet
  prompts), `run.py` + `scripts/eval.py` (the fabricated monolith, hardcoded
  `SCOPE=["struts","db","jenkins"]`, bound to the delete-set), `prompts.RED_ORCHESTRATOR` +
  `BLUE_ORCHESTRATOR`.
- `red_tools.py` (842 lines) is the key knot: it is the `_CTX`/`set_range_context` cheat-sheet
  (hands red `objective_host`/`objective_cve`/`in_scope_pivots`) + the dead cascade tools +
  `_SERVICE_CVE`/`EXPLOIT_REGISTRY` host→CVE table — ALL slop — PLUS four real HTTP-RCE weapons
  the keeper layer still uses: `exploit_apache_cgi`, `exploit_weblogic`, `http_rce_request`,
  `http_rce_cves` (imported by `live_weapon`, `live_lateral`, keyed by the CVE red inferred).
- Incalmo-completeness gap: the FRAMEWORK is Incalmo-grade (belief/frontier, works_on cred
  pivots, MSF catalog, multi-modality weapons) but the real response arsenal is 3 CVEs
  (`live_weapon.ARSENAL`) + whatever MSF yields. "Full toolkit" means growing the arsenal/MSF
  coverage to span the range's service catalog.

### UNTRUSTED blue — two clean full-toolkit engines exist; pick one, kill the demo.
- Clean engines: `live_blue_agent.BlueAgent` (autonomous SOC/IR loop, lossy-sensor-only, full
  real toolkit: investigate/hunt/isolate/kill_session/revoke/rotate/block_ip/decoy/counter_recon/
  wait, gate-mediated, can miss/wait) and `live_swarm.run_blue_frontier_loop` +
  `blue_response.BlueResponseFrontier` (symmetric defensive frontier).
- Real toolkit (keep): `blue_contain` (CAGE eviction ladder: remove_foothold/rollback_host/
  close_vector on live containers), `live_blue` (gated cred-revoke + MTD), `blue_fast`
  (deterministic MTTC/MTTD tier), `blue_llm` (slow tier), `blue_counter_recon` (gated active
  defense), `blue_detect` (oracle/regex, ablation-only), `deception`, and the real detector
  `sensor_stack` (4 sensor formats, 8 kill-chain tactics, measured recall, blind to
  `gate.allow`, hostname-shadowing defenses) — blue detection is NOT capped at 3 signatures
  (that was the `sensor_real` precursor).
- SLOP (delete/fold): `blue_agent.run_blue_agent`/`run_blue_scripted` (the demo blue that
  fabricates its own containment and forces `isolate_host`).

### UNTRUSTED range — both halves of "MHBench + real" exist, unmarried.
- `range_gen.py`: the live Docker generator — REAL vetted vulnerable images (boot-clean rule
  `vetting.is_vetted`, real CVE exploitation), `netmodel` reachability (depth-≥2 crown as a
  physical L3 fact: `reachable(attacker,crown) and not reachable(...,without=pivot)`), a
  real-CVE crown spine. BUT bespoke topology from hand-authored `config/range_pool.yaml`, NOT
  MHBench, and it carries hardcoded entry hosts (`_ENTRY_HOSTS={struts,webrce,weblogic,gitlab}`).
- `topo_to_compose.py` + `mhbench_schema.py`: a GENUINE MHBench adapter — consumes a vendored
  MHBench `NetworkTopology` (30+ validated fixtures under `tests/fixtures/mhbench/`): multi-flag
  `JSONDataExfiltrationGoal`s, ground-truth `attack_paths` (red-blind), `User.ssh_keys`
  cred-pivots, SudoBaron/WriteablePasswd privesc, real segmentation (internal:true, isolated
  OOS, masq-off ingress), real sshd for pivots, floor re-derivable (oos=0). BUT host images are
  alpine STUBS with vulns as `SIMULATED` labels — only ssh is real, the vuln-pop is not.
- `netmodel.py`: the reachability substrate — real CIDR, computed reachability. Clean keep.
- The red frontier is ALREADY MHBench-shaped: `env_state.handle_SSHKeysFound`/
  `handle_PrivescVulnFound` match MHBench's `ssh_keys.works_on` + SudoBaron/WriteablePasswd
  one-to-one. The IR and the engine were built to connect; they are just not married on the
  live path.

### Co-evolution / populations — red-pop real; blue-pop absent; two-pop loop absent.
- `population.py`: a mature RED MAP-Elites population — `Genome{prompt,memory}`, red operator
  personas, novelty-weighted + frequency-penalized selection, `MapElitesArchive`, `Evolver`
  with checkpoint/resume, degeneracy gate, inheritance proofs. `Evolver.tick` already exposes
  `last_gen_events` as the hook for a co-evolving blue.
- `arms_series.py`: the ONE cross-episode series spine (family rotation, checkpoint/resume,
  arsenal archive, floor invariant). `arms_race.py`: evasion-vs-learned-monitor dynamics +
  `LearnedMonitor` (refitting signature set) + IR scoreboard (dwell/MTTC/reentry). `coevolve.py`:
  a DETERMINISTIC MODEL of two-sided memory adaptation (labeled, not learned). `env_coevo.py`:
  range-difficulty curriculum (a third evolving axis).
- The gap: blue is a signature set / memory / scripted model, NOT an LLM MAP-Elites population;
  there is no two-archive red-pop-vs-blue-pop loop; real-run co-evolution is an honest null.
- Confirmation-bias leaks (fix #4): `population.manipulation_score` reads red's own
  `red.deception.summary`; `population.score_fitness` + `arms_race` detect crown/exfil via the
  dead cascade vocabulary (`db_exploit`/`enumerate_db`/`exfiltrate`), not the frontier/spine
  vocabulary (`state.mutate` foothold/lateral/exfil, `crown.access`).

---

## What "ready" means — and why `make test` green is NOT it

The bloat happened because `make test` green was treated as the goal: the suite ran nearly every
module's selftest, so keeping it green made every module load-bearing, and that is why the slop
survived. Do not repeat this.

- `make test` is a SMOKE check only — necessary, trivially true, and REBUILT to the canonical set.
  A module's selftest passing is NEVER a reason to keep the module. The trust-boundary partition
  decides what survives; `make test` is rebuilt to match the survivors, not the reverse. Deleting
  a module and its make-test line in the same commit is correct even though it "reduces coverage."
- Readiness is RE-DERIVATION AT SOURCE by a checker that trusts neither the floor nor the agents,
  plus the structural facts — none of which a green selftest can stand in for:
  1. The floor policy guarantee re-derived COLD from the hash chain on REAL runs (not a fixture):
     `reverify_floor` → `oos_executed == 0` where the floor mediates, chain verified.
  2. The falsification battery still BITES on the consolidated engine: a fabricated claim is
     flagged, forged telemetry breaks the chain, an honest run is not false-flagged
     (`prove_falsification`, `redteam_gate`, the reconciler) — re-run cold after every move.
  3. One of each, proven by the import graph / grep (one attacker loop, one blue loop, one range
     generator, one gate, one log, one telemetry, one reconciler, one spine, one effect path),
     and zero hardcoded hosts/CVEs on the live path.
  4. The thesis claims are actually MEASURABLE on the running range (each produces a re-derivable
     number or is labeled pending) — the range can show the floor LEAKING, not only holding.

If `make test` is green but any of 1-4 is not true at source, the build is NOT ready. If a module
is slop by the trust partition but its selftest is green, it still goes. Every phase's done-check
below is a source re-derivation or a structural fact, never "the suite passed."

## The build (ordered; each step has a source-checkable done-check)

Phases 1-4 are convergence (collapse to one of each, kill the cheat-sheet). Phases 5-6 are the
two genuine builds the mandate needs (MHBench+real range; blue population + two-pop co-evolution).
Phase 7 re-arms the instrument. `make test` is kept runnable per commit as a smoke only and is
rebuilt to the canonical set as modules are cut (see "What 'ready' means" above); it is never the
done-signal. Nothing faked at any step.

### Phase 1 — Excise the cheat-sheet lineage (inv #5, no-hardcoding)
- Port the four real weapons out of `red_tools` into the weapon layer (`live_weapon`/`arsenal`),
  keyed by CVE: `exploit_apache_cgi`, `exploit_weblogic`, `http_rce_request`, `http_rce_cves`.
- Delete `red_agent.py`, `red_tools.py`, `run.py`, `scripts/eval.py`, and
  `prompts.RED_ORCHESTRATOR` + `BLUE_ORCHESTRATOR`.
- Done: `grep -rn "red_tools\|red_agent\|RED_ORCHESTRATOR\|BLUE_ORCHESTRATOR\|from run import"`
  over the live tree returns nothing (the cheat-sheet is gone at source); each deleted module's
  `make test` line is dropped in the same commit (coverage shrinking is correct here).

### Phase 2 — One attacker engine (the autonomous agent)
- The ONE red is the autonomous agent `live_agent.run_red_agent` (free action each turn over an
  injected full toolkit), NOT the frontier menu. Fold the belief machinery (`env_state` +
  `attack_graph_service` + the anti-beeline/vantage logic of `run_red_frontier_loop`) IN as the
  agent's situational-awareness layer: the agent sees its discovered belief and a candidate
  surface, but may compose any gate-mediated action, not only menu items. Extract `tier_call` +
  `real_struts_foothold` + `_own`/`_gw`/`live_recon_scan` from `live_swarm.py`; fold
  `live_red`'s booted-range executors (`scan_subnet`, the real exec channel) in as the agent's
  live tools; delete `run_red_cascade`. Keep `red_recon` as the deterministic dry mode.
- Done: exactly one red driving-loop in `swarm/`; it is objective-blind (no map/scope/crown in
  the prompt; belief grows only from discovery events), and the enterprise multi-hop case (crown
  reached at depth ≥2 from a non-entry vantage) still passes against it.

### Phase 2.5 — Real C2 infrastructure (Sliver)
- Stand up a real Sliver C2 server as a container on red's infra network; a foothold/`LateralMove`
  installs a real Sliver implant that beacons back, replacing the out-of-band docker-exec marker
  as the confirmation signal (`beacon.py` becomes a real Sliver callback, the `check_new_agents`
  pattern made real). The implant session is red's earned channel: all post-foothold actions and
  self-authored tools go down it, gate-mediated and logged.
- One shared C2 for v1; the C2 handle is built per-actor-ready for the deferred multi-APT phase.
  `caldera_operator` (attic) is not revived.
- Done: a foothold lands a real implant that beacons to the real C2; a post-foothold action runs
  via the implant session, is gate-mediated and hash-chain-logged, and the beacon is visible to
  `sensor_stack` and the reconciler; a C2 action at an out-of-scope target is recorded as a result
  (not prevented by fiat).

### Phase 3 — One defender engine (the autonomous agent, symmetric to red)
- The ONE blue is the autonomous agent `live_blue_agent.BlueAgent` (free action each turn over
  the full SOC toolkit, lossy-sensor view only) — symmetric to red, and the right substrate for
  an agent that must invent tools. Fold `run_blue_frontier_loop` + `blue_response`'s response
  logic in as blue's situational awareness (not a ceiling); delete `run_blue_cascade` and the
  demo `blue_agent.run_blue_agent/scripted`. Blue's prompt stays the clean `BLUE_SYS` (no leak).
- Done: exactly one blue driving-loop in `swarm/`; it decides only from its lossy sensor picture
  + its own investigations, every action gate-mediated.

### Phase 3.5 — Tool authoring (the "write their own tools" capability)
- Give both agents a first-class gate-mediated capability to AUTHOR a new tool at runtime: the
  agent writes a script/exploit, it runs through the ONE effect path (the earned shell `exec`
  for red; blue's gated effectors), is logged in full (logs-for-everything), and — on success —
  is saved as a reusable, named tool the agent (and its lineage) can call again. This generalizes
  the earned-channel free-form command execution that already exists into reusable, inheritable
  tools; it does not add a new effect path.
- Instrument constraint (non-negotiable): an authored tool's execution is DISPATCHED through the
  one gate and hash-chain-logged like any other action, so it is attributable and re-derivable.
  This is what keeps a penetration a provable RESULT rather than noise. It is NOT a requirement
  that the tool be blocked — whether the floor holds is the experiment (claims 2/4).
- Done: a red- or blue-authored tool runs, is logged in full, and persists for reuse; and whatever
  its outcome at an out-of-scope target — floor held (segmentation dropped it), floor-construction
  flaw found (it crossed the wire: `oos_tcp_reaches` > 0), or harm assembled from allowed actions —
  that outcome is faithfully recorded and re-derivable cold. The only failure is an authored-tool
  effect that leaves NO gate record.

### Phase 4 — Verb axis + one effect path (inv #1, #3)
- Add the verb axis to the gate: `scope_by_actor` carries a per-verb grant (read vs mutate);
  `dispatch` enforces it; mutate default-denied where only read is granted; back it with
  read-only bind-mounts on crown/OOS in the one compose emitter.
- Route every `subprocess`/`docker` effect so that only one gate-dispatched primitive causes an
  external effect; every other module requests effects through it (today docker calls are
  scattered across ~15 modules incl. `blue_contain`, `live_msf`, `live_pivot`, `range_runtime`).
  Bring `range_runtime` (docker compose up/down) under a `range.lifecycle` verb the TCB owns.
- Done: gate self-test has a read-allowed/mutate-denied case; `grep` for subprocess/docker
  outside the single effect site returns only that site.

### Phase 5 — One range, sourced from MHBench with REAL images (BUILD)
- Make the MHBench adapter (`topo_to_compose`) the one generator; retire `live_terrain` and
  fold `range_gen`'s machinery INTO the adapter: replace the alpine `SIMULATED`-vuln stubs with
  `range_gen`'s vetted real-exploit image mapping (MHBench host service/vuln → a boot-clean
  vetted Docker image), keeping `netmodel` reachability, the boot-clean rule, and the real-CVE
  crown spine. Source topology from the MHBench fixtures/IR, not `range_pool.yaml`.
- Remove `range_gen._ENTRY_HOSTS` and every remaining host/CVE literal from the range path;
  the entry/crown/CVE are drawn from the MHBench topology + the vetted-image mapping, never named.
- Done: one generator; a booted range from an MHBench fixture has REAL vulnerable services on
  the attack path (not alpine stubs), `reverify_floor` re-derives oos=0, and the literal-host
  scan over the range path is clean.

### Phase 6 — Red AND blue as co-evolving populations (THE BUILD)
- Extend the genome to `{prompt, memory, authored_tools}` so evolution selects over strategy
  AND the tools each side invents (Phase 3.5) — a tool that evaded/contained well is inherited
  and mutated by the lineage, which is how an open-ended toolkit co-evolves. `Genome`/
  `MapElitesArchive`/`Evolver`/checkpoint stay generic; this is an added field + its inheritance.
- Generalize `population.py` over a `side`: reuse that machinery verbatim; add blue defender
  personas, a blue behavior descriptor (e.g. detection breadth × containment aggressiveness ×
  FP-cost × crown-protected), and a blue `score_fitness` sourced from TELEMETRY (`sensor_stack`
  recall, `arms_race.scoreboard` dwell/MTTC, crown held vs lost) — never a self-report.
- Build the two-archive coevolutionary loop on the `arms_series` spine: each generation the
  evaluate() is a real duel of one red genome vs one blue genome on one booted MHBench range;
  red-pop evolves against the current blue elite(s) and blue-pop against the current red
  elite(s); both archives checkpoint. `env_coevo` folds in as the optional range-difficulty
  axis. `coevolve`'s deterministic model and `arms_race.LearnedMonitor` become ablation
  baselines, not the headline.
- Fix #4 in the same pass: rewire `manipulation_score` off `red.deception.summary` to the
  reconciler/blue's logged `detect.posture`; rewire `score_fitness`/`arms_race._MALICIOUS` off
  the cascade vocabulary onto spine-confirmed events (`state.mutate`, `crown.access`,
  `confirm`).
- Done: a red population AND a blue population, both MAP-Elites, co-evolve on the series spine;
  no selection term reads a red/blue self-report; the evasion-vs-opponent curve moves under a
  real adapting opponent (reflexivity), reported as the invariant ("the gate stays flat at 0
  under adaptation"), never "co-evolution works" beyond what the data shows.

### Phase 7 — Re-arm the instrument cold
- Re-run `prove_falsification`, `redteam_gate`, `reverify_floor` COLD on the consolidated engine;
  rebuild `make test` to the canonical set only (drop every cut module's line in the same commit).
- Done (readiness, at source, not "the suite passed"): the falsification battery catches every
  planted lie and clears an honest run; the floor re-derives `oos_executed == 0` cold on a real
  run with the chain verified; the import graph shows exactly one attacker loop, one blue loop,
  one range generator, one gate (with the verb axis), one log, one telemetry capture, one
  reconciler, one spine, one effect path; zero hardcoded hosts/CVEs on the live path; and the
  four thesis claims each produce a re-derivable number or are labeled pending.

---

## What is already done (do not redo)
Six of seven invariants hold in the TCB; the auditor-drift liability is closed; the belief-
frontier red is objective-blind and anti-beeline; blue already has a real multi-sensor detector
and a real eviction toolkit; the MHBench IR is vendored and the adapter emits real segmentation
with a re-derivable floor; the red MAP-Elites population + series spine + checkpoint/resume work.
The job is to converge these onto one path and finish the two unfinished pillars (MHBench-real
range; blue population + two-population co-evolution), not to rebuild them.
