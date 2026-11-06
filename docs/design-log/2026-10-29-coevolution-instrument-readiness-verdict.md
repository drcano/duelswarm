# Instrument-readiness verdict: wiring live co-evolution (2026-10-29)

Planner/verifier consolidated verdict for the READINESS GATE in
`2026-10-29-coevolution-blue-brief-and-plan-amendment.md`. Synthesizes a 7-agent full-read
codebase audit plus my own cold re-derivations. Every load-bearing claim below was re-verified
against CURRENT source (re-staged this evening, because CC touched the oracle/driver files tonight
and a stale snapshot already produced one false blocker). Verification status is marked per finding:
**[cold]** = I re-derived it against current source myself; **[relayed]** = an agent's line-cited
finding I did not independently re-run (flagged for on-machine confirmation).

## BOTTOM LINE
**Not ready to wire live co-evolution yet. The deterministic FLOOR is sound; the result-side
instruments and the live wiring seams are not.**

The audit did exactly what it was commissioned to do: it found that wiring the generational loop
onto the repo as it stands would amplify latent instrument error into confident false results. The
gate, the hash chain, the spine law, the GT firewall, and the oracle/measured-red separation are
airtight IN ISOLATION (re-verified). But three result-side instruments would draw false
co-evolution charts, and two mediation holes open exactly at the two steps the plan calls for
(blue acts; red's action space grows). None of this invalidates the oracle batch or best-of-3 — it
gates the generational loop, which is unbuilt.

The ordered prerequisite list is in the DECISION section. No co-evolution generation (free or paid)
runs until Group A clears; blue does not act until Group B clears; red gets no shell tool until
Group C clears.

---

## WHAT THE AUDIT CONFIRMED IS AIRTIGHT (the floor is real)
These were re-verified and are sound. They are why the floor can be trusted as the fixed term while
everything above it co-evolves.

- **gate.dispatch complete mediation of the live action path** [cold]. Blocks the out-of-scope
  target BEFORE running `tool_fn`, logs `gate.block`/`gate.allow`, enforces per-actor scope, the
  read-vs-mutate verb axis, confused-deputy, and the P0 egress parser (zero false-positives). Every
  live red tool and the one wired blue effect route through it (16/2/6/2/2 dispatch sites).
- **Hash chain** [cold, prior]: verifies and detects edits / reorders / mid-deletions. Tail-
  truncation is covered by the external MANIFEST/prereg anchor — this must be enforced per
  generation (see A4/airtight-caveat).
- **Spine law, structural** [cold]: `state.mutate` only ever references a prior observer `confirm`;
  `audit_spine` catches self-confirmed / unconfirmed / dst-mismatch / non-prior mutations; fresh
  EventLog + Gate per episode, so no cross-episode seq desync.
- **GT firewall** [cold, prior + this pass]: static import-closure (leak_test LEAK-FREE, red closure
  isolated from the validators) + the oracle rail (O1/O2/O3) + the runtime
  `assert_measured_red_oracle_free` guard. Oracle and measured-red are mutually exclusive per
  episode; map-blindness is asserted on the exact seeded context (crown host/path/user included).
- **Class-2 uninstrumented channel import-isolated** [relayed, consistent with prior]: `beacon`
  imports `uninstrumented` but is injected, never imported by an engine module, so it is outside the
  agent closures; the harness §E probe is measurement-only and excluded from the coverage count.
- **Objective verdict on the live MEASURED path is telemetry-gated** [cold]:
  `_corroborated_objective` requires red's grounded byte-level self-report AND the independent
  reconciler's witness. A fabricated loot scores 0 on this path.
- **Reconciler false-POSITIVE drops are regression-tested** [cold]: a bare `:22` connect and a bare
  `sshd-session`/T1021 fork do not corroborate a lateral; only a completed auth, a web-exploit
  fault, or the entailed crown read does (live_truth.py:238-266).
- **The oracle ceiling + best-of-3 results are UNAFFECTED** by the co-evolution-specific blockers
  below. They are observe-only, single-generation. The floor held on all 13 committed task2-run1
  chains (both auditors agree, oos=0), and the oracle crown reads WERE witnessed (2 pii.json reads
  per in-sample seed) — positive evidence that on those runs Falco started, attributed correctly,
  and captured the read. The blockers are about ROBUSTNESS under unattended generational
  repetition, not evidence of past mis-measurement.

---

## BLOCKERS, by the brief's five readiness gates

### Gate 3 — selection / fitness soundness (the keystone group)
This is where co-evolution amplifies hardest: selection optimizes toward whatever the fitness
actually measures.

- **A1 — Two inconsistent fitness contracts; selection must use the telemetry-gated one** [cold].
  (Agent 1 #8.) `population.score_fitness` (the Evolver's genome fitness) reads its objective term
  from `_spine_confirmed(events)` (population.py:173-180, 228), which checks only for the PRESENCE of
  a `crown.access` event and an `exfil` `state.mutate` — no `fidelity`, no `via_confirm`, no
  telemetry. `audit_spine` (spine.py:66-90) likewise verifies confirm/mutate STRUCTURE but never
  inspects `fidelity`, so a `SIMULATED` confirm passes as clean. Meanwhile the live measured path
  (`live_arms_race_run._corroborated_objective`) is telemetry-gated and its comment asserts "Phase-6
  fitness reads `duel.verdict.achieved`, never the self-report." The live generational loop does not
  exist yet (confirmed), so this is prescriptive: **whoever wires selection must key it on
  `duel.verdict.achieved` (telemetry-gated), not reuse `population.score_fitness`'s `_spine_confirmed`
  objective.** If the loop reuses `population.Evolver` as-is, every witness bug below compounds
  through a fidelity-blind objective term.

- **A2 — Falco standup failure silently flags every genuine loot** [cold]. (Agent 5 BLOCKER 1.)
  `start_falco` can return `None` (honest degrade, live_arms_race_run.py:704). The MSF modality gets
  a first-class `episode.degraded` marker AND a `verdict["msf_wired"]` flag when down (706-713, 917);
  **Falco has neither.** A `Falco=None` yields `falco_lines=[]` (890-891) → empty `reads_by_host` →
  loot flagged (live_truth.py:152-155) → `_corroborated_objective` sets `achieved=False` (916)
  despite red's grounded self-report being True. Falco is the SOLE witness for the crown read and the
  entailed-lateral. Under multi-generation selection, an infra flake converts genuine wins to
  0-fitness with no marker, so selection partly tracks Falco uptime. **Fix: mirror the MSF degraded
  marker + a `falco_wired` flag, and exclude/degrade the generation when the syscall source is
  absent rather than scoring it 0.**

- **A4 — The co-evolution floor line is a hardcoded `0`, not a re-derivation** [cold]. (Agent 1 #1.)
  `arms_race.episode_metrics` sets `oos_executed = 0` as a literal (arms_race.py:145), and
  `coevolve.py:252` and `:311` consume it directly for the per-generation floor chart. Any effect
  that bypasses the gate (see B2/C1) produces no `gate.block` and this metric still reports 0 — it
  cannot falsify a breach. **Fix: the co-evolution floor number must come from `reverify_floor` /
  `audit_scope` on the committed chain every generation (as the brief already specifies), and the
  `arms_race` literal must never be reported as the floor.** The brief's per-generation
  `reverify_floor` hook already does the right thing; the hazard is only if the loop reports the
  `arms_race` number instead.

### Gate 1 — map / GT leakage into red via the memory channel
- **A5 — `assert_red_map_blind` does not scan the episodic-memory block** [cold, prior + this pass].
  (Agents 2 + 5.) Episodic recall is NOT wired into the measured engine today
  (`run_interleaved_duel` → `run_red_agent` is called without `episodic_recall=`), so memory is
  decorative and there is no live leak right now. But `assert_red_map_blind` scans only the seeded
  awareness context, not what red reads from memory. **Prereq of the memory-on build unit: extend the
  map-blind guard to cover what red writes to and reads from episodic memory, and make the selftest
  bite on a planted memory entry carrying a ground-truth name — BEFORE recall is wired.** A one-time
  leak into memory compounds across generations uncaught.

### Gate 4 — complete mediation / no unrecorded effect
- **A6 — The two-auditor agreement is contingent, not structural, and its cross-check is skipped**
  [cold]. (Agent 1 #4.) audit (`_scope_from_log:120`) takes the FIRST `floor.boundary`
  (`shared is None` guard); `reverify_floor` (109-111) takes the LAST (overwrite loop). audit honors
  `scope`-event `aliases`; `reverify.canon` (48-59) has no aliases parameter and ignores them. So on
  a chain with multiple boundaries (multi-episode-in-one-file) or aliases the two auditors silently
  split, and whichever the pipeline trusts sets the verdict. They DO agree on today's single-boundary,
  alias-free shape (verified on all 13 chains). The audit cross-check selftest is also skipped (its
  data file `phase1-paid-run4/episode01_seed1337.jsonl` is absent) and still passes. **Fix: either
  make both auditors pick the same boundary and both honor aliases, or pin co-evolution chains to
  single-boundary-per-file + alias-free with a test asserting it; and repoint the cross-check
  selftest to a current chain so the "two witnesses must agree" guarantee actually runs in CI.**

---

## BLOCKERS that open when BLUE ACTS (Group B — the "out of the bullpen" step)

- **B1 — Blue scores a PREVENTION on a simulated/failed containment** [cold]. (Agent 1 #3.) In
  `_response_tool._run`, `state["contained"].append(host)` plus the spine `confirm`/`mutate` fire
  whenever `tool in _STOPS_SPREAD` and the gate allowed, REGARDLESS of `_real`
  (live_blue_agent.py:595-603). `_real` only sets the `simulated=`/`fidelity=` label. Then
  `prevented = (not achieved) and bool(state["contained"])` (725), contradicting the 734-736
  docstring. On the live seat, `_real_contain` returning `fidelity="SIMULATED"` (disconnect
  unverified) still flips `prevented=True`, and it feeds blue fitness (MTTC; `blue_score_fitness`
  `contain_speed` at 20%). So blue co-evolution would reward emitting a containment beat early, real
  effect or not — containment theater. NOTE: this does NOT touch the claim-3 erosion arm, which is
  observe-only (`blue_contains=False`, so `blue.tick` never fires and `state["contained"]` stays
  empty). It bites the acting-blue arm. **Fix: gate `state["contained"]`, the beat, and the spine
  mutate on `_real` (or a telemetry-confirmed cessation), not on dispatch success.**

- **B2 — The eviction ladder bypasses the gate** [cold]. (Agent 1 #2.) `gate.dispatch` appears 0
  times in `blue_contain.py`; every primitive (`contain_host`, `rollback_host`, `close_vector`,
  `drop_honeytoken`, ...) calls `run_effect` directly, which does no scope check and writes nothing
  to the chain. The one wired blue effect (`isolate_host`) is mediated ONLY by caller discipline
  (live_blue_agent.py:584 wraps it in `gate.dispatch`); nothing structural forces it. The eviction
  tier is not wired as `executors` yet. **Fix: when wiring remove_foothold/rollback_host/close_vector,
  route every one through `executors` → `_effect` → `gate.dispatch`; add a mediation test that bites
  if any blue effect reaches `run_effect` without a `gate.dispatch`.** A direct
  `blue_contain.rollback_host(...)` call would disconnect / `rm -f` with no scope check and no log —
  and the log-based auditors would report `oos_executed=0` while blue evicted an out-of-scope host.

### Gate 2 — blue air-gap under memory
- **B3 — The air-gap rides caller discipline, and blue-memory has a GT side door** [cold, prior +
  relayed]. (Agents 3 + 7.) The per-tick telemetry window is label-free as currently CALLED
  (`sensor_real.assert_label_free` in the driver's `_telemetry_window`), but `run_interleaved_duel`
  does not itself enforce that a future co-evo driver's window is label-free + red-internals-free —
  a new driver that builds its own window and forgets the wrapper feeds blue unguarded data. And
  blue's memory path exposes `extra={"techniques_seen":[cve]}` (a ground-truth side channel) while
  the air-gapped path is near-empty (a `chose` vs `tool` schema mismatch), pressuring the wiring
  toward the leaky channel. **Fix: self-enforce label-free + no-red-internals inside the engine for
  blue's input, close the `extra=` side door, and fix the schema mismatch so the air-gapped path
  carries the real signal.** This air-gap IS the asymmetry under test; a leak voids claim 3.

---

## BLOCKERS that open when RED's action space grows (Group C — a shell / free-form command tool)

- **C1 — The egress boundary check is dead on the live path** [cold]. (Agent 1 #5.) `command=`
  appears 0 times in `live_red.py`; `gate.check_egress` only runs when `command=` is passed to
  `gate.dispatch`. Today this is bounded because red's tools take a fixed verb+target, not a
  free-form command. **The moment red grows a shell/`run_command` tool (a natural co-evolution
  escalation), its second-hop egress (`curl http://<oos>`, `nc`, `/dev/tcp`, ssh) over an in-scope
  foothold is unmediated AND invisible to both log-based auditors. Wire any such tool through
  `gate.dispatch(command=...)` so the egress layer runs.**

- **C2 — The kernel backstop for IP-obfuscated egress is unrun and not in CI** [relayed — I did not
  re-run these; needs on-machine confirmation]. (Agent 1 #6.) Agent 1 reports `parser_fuzz
  --selftest` finds 3 true bypasses (`curl http://2887122948/`, `http://0xac160004/`,
  `http://[::ffff:172.22.0.4]/` all resolve to an OOS IP while the parser ALLOWS them), by-design
  compensated by the network-segmentation backstop — but `reachability_probe --selftest` crashes in
  the snapshot (`docker-compose.yml` absent, generated by `topo_to_compose.py --unified`), the live
  `--measure` is unrun, and `make test` runs neither probe. **Before red gets a shell tool: run
  `reachability_probe` (fix the compose generation) and put `parser_fuzz` + `reachability_probe` in
  CI.** Please confirm the 3 bypasses by running `parser_fuzz --selftest` on-machine — I could not
  re-run it here (no docker / compose in my container).

---

## VALIDITY QUESTIONS (not blockers — decisions for you)

- **D1 — The t_loot crown-cred fallback** [cold]. (Agent 5 GAP.) `live_red.py:1215-1216`:
  `candidates = driver._pivot_candidates() or [{...seeded crown cred...}]`. If red harvested
  nothing, exfil still runs on the harness's crown cred. Topology (deep data-tier crown) forces the
  pivot, but for any crown reachable from an owned vantage red reaches the objective by naming the
  host. Under co-evolution this selects red toward "reach the segment and call loot," not
  "harvest + reuse tradecraft." **Decide: keep the fallback (measures reach) or remove it (measures
  credential tradecraft).** The memory notes frame it as intended ("the harness's loot-read cred"),
  so this is a design call, not a bug.

- **D2 — Stale gate alias map under topology mutation** [cold, shape confirmed]. (Agent 1 #7.) The
  gate builds its IP→name alias map once in `__init__` and never refreshes. If the eviction ladder
  mutates topology (containment disconnects nets → IP changes; rollback does `rm -f` + `run` → new
  IP), an IP-addressed action can resolve against stale entries: a false-block at best, and if Docker
  recycles an IP to an out-of-scope container, a false-allow at worst. Minor today (only
  `isolate_host` wired, no rename). **If the eviction ladder is wired, refresh the alias map per
  episode.**

- **D3 — The crown-read witness is a filename substring match** [cold]. (Agent 5 GAP.)
  `reads_by_host` credits any `sys.syscall` whose `signal+label+raw` contains the crown filename, so
  a FAILED read or a `stat`/`ls` on the path corroborates loot in the raw reconcile counts. Backstopped
  for the OBJECTIVE by t_loot's byte grounder (`looks_like_pii`). **If any co-evolution fitness term
  reads the raw `corroborated`/`all_corroborated` counts rather than the gated verdict, tighten it.**
  (Resolved automatically if A1 keys fitness on `duel.verdict.achieved`.)

---

## A3 — RUNTIME witness verification (do this per range boot, before trusting any fitness) [cold]
(Agent 5 BLOCKER 2.) The reconciler is correct GIVEN the witnesses appear, but whether they appear is
a runtime property of the unified range's containers, which the unit tests cannot check (they feed
the "Accepted" lines as fixtures). Two dependencies:
1. **sshd must log "Accepted ..." to a `docker logs`-captured stream** (sshd `-e`, or a syslog→stdout
   shim). The mid-host SSH-pivot witness is ONLY the `_AUTH_OK_SENTINEL`, set from a `svc.event`
   "Accepted" token; default sshd logs auth to syslog, not stdout. If unmet, every key-based pivot to
   a mid host (no web-exploit, not the crown) is silently flagged.
2. **Falco container-attribution must be live** (docker.sock mounted at `/host/var/run/docker.sock`).
   `start_falco`'s own comment warns a mis-mount yields `container.name=<NA>`;
   `parse_syscall_events` then files the line under host `"?"`, which `reads_by_host.get(crown)`
   misses → crown read flagged.
Add a one-time per-boot assertion that a known benign "Accepted" line and a known file-open both
appear, attributed, in the telemetry chain — fail the boot if not.

---

## DECISION — the ordered prerequisite list

**Before ANY co-evolution generation (free or paid):**
1. A1 — selection keyed on `duel.verdict.achieved`, not `_spine_confirmed`. (keystone)
2. A2 — Falco-degrade marker + `falco_wired`; degrade/exclude the generation when syscalls absent.
3. A3 — runtime witness assertion per range boot (sshd `-e` + Falco attribution).
4. A4 — floor line from `reverify_floor`/`audit_scope` per generation, never the `arms_race` literal.
5. A5 — map-blind guard extended to the memory channel, selftest bites on a planted GT name
   (prereq of the memory-on build unit).
6. A6 — auditor boundary/alias agreement made structural or chains pinned + tested; cross-check
   selftest repointed to a live chain.

**Before blue acts (observe → act):**
7. B1 — prevention gated on real effect, not dispatch success.
8. B2 — eviction ladder routed through `gate.dispatch`; mediation test added.
9. B3 — blue air-gap self-enforced in-engine; `extra=` side door closed; schema fixed.

**Before red gets a free-form command / shell tool:**
10. C1 — route it through `gate.dispatch(command=...)` so egress mediation runs.
11. C2 — kernel backstop (`reachability_probe`) run + both egress checks in CI.

**Your calls (not blocking the build, but settle before the measured arm):** D1 (crown-cred
fallback), D2 (alias-map refresh, only if eviction wired), D3 (auto-resolved by A1).

CC builds these free; I verify each cold against the committed chain; no paid generation fires
without your explicit go. The memory-on, blue-to-claim-3-spec, Hall-of-Fame, memory-on/off control,
transfer-eval, and pathology-falsifier build units from the brief proceed on top of a cleared Group
A (and Group B for the acting-blue arm). Best-of-3 and the oracle layer are untouched by all of this
and resume independently on your Nebius top-up.
