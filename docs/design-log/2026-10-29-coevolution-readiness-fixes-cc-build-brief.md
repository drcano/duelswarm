# CC build brief: co-evolution readiness fixes (2026-10-29)

Turns the readiness verdict (`2026-10-29-coevolution-instrument-readiness-verdict.md`) into build
units for CC. Each unit states the current behavior (with the exact anchor the planner verified cold
this session), the required behavior, an implementation note, and the ACCEPTANCE test the planner
re-derives cold before the unit is trusted. Order is binding: Group A clears before any co-evolution
generation (free or paid); Group B before blue acts; Group C before red gets a free-form command
tool. No paid generation fires without Dante's explicit go.

Invariants unchanged: floor/TCB/log frozen; GT firewall holds including the memory channel;
`oos_executed` is measured, never targeted; every result re-derivable cold from the chain + I/O
sidecar + memory store by a party trusting neither agent.

---

## READ FIRST — the frozen-TCB gate
Editing a frozen TCB file is a dated prereg amendment (seq 50+) that records the file's new SHA256
BEFORE the edit is trusted. Frozen: `gate.py`, `eventlog.py`, `spine.py`, `audit.py`,
`reverify_floor.py`, `scripts/mediation/static_coverage.py`.

Of the units below, implemented as specified, exactly ONE must be a dated amendment:
- **A5** edits `live_agent.assert_red_map_blind` (the pinned red map-blindness guard). This is the
  same dated-amendment regime as the Task-1 `live_agent` change (seq 47). It needs a seq-50+
  amendment recording the new `live_agent.py` hash.

Every other unit is written to AVOID touching a frozen file:
- **A6** uses a chain-constraint + a new non-TCB parity test, NOT an edit to `audit.py` /
  `reverify_floor.py` (the invasive TCB-edit alternative is noted but not recommended).
- **A1/A4** live in the new co-evo driver and in `population.py` / `arms_race.py` / `coevolve.py`,
  none of which are frozen.
- **B1/B2/B3** live in `live_blue_agent.py` / `blue_contain.py` / blue memory, none frozen.
- **C1** passes `command=` at a new call site; `gate.check_egress` already exists, so `gate.py` is
  not edited.

**Pending amendment batch (Dante's go):** A5, plus the still-open app_crown_3hop held-out decision
(replace vs drop, from the earlier doc), can fold into one seq-50 amendment. Recommend one amendment
covering both when Dante gives the word.

---

## GROUP A — before ANY co-evolution generation

### A1 — Selection keyed on the telemetry-gated verdict (keystone)
- **Current:** `population.score_fitness` reads its objective term from `_spine_confirmed(events)`
  (`population.py:173-180, 228`) — presence of a `crown.access` + an `exfil` `state.mutate`, with no
  `fidelity` / `via_confirm` / telemetry check. `audit_spine` (`spine.py:66-90`) never inspects
  `fidelity`, so a `SIMULATED` confirm passes clean. The live generational loop does not exist yet,
  so nothing enforces which fitness it will use.
- **Required:** the co-evo driver computes each red genome's objective term from
  `duel["verdict"]["achieved"]` (the `_corroborated_objective` telemetry-gated flag,
  `live_arms_race_run.py:670-688`), NOT `_spine_confirmed`. Behavioral descriptors (depth / technique
  / exploit / stealth) may remain as shaping terms. Add a hard assertion in the driver: a reconciler
  verdict is present on the duel result before any fitness is computed; raise if absent.
- **Implement:** `fitness_objective = 1.0 if duel["verdict"]["achieved"] else 0.0`. Keep
  `score_fitness`'s `_spine_confirmed` objective for the dry/offline shaping path only, or refactor
  `score_fitness` to take an injected objective term so the live path passes the gated one. Do not
  leave a code path where the live loop can read the fidelity-blind objective.
- **Acceptance (cold):** on a crafted chain where red emits `crown.access` + `exfil` mutate but the
  reconciler FLAGS the loot (no witness), the genome objective term re-derives to 0.0, not 1.0; and
  grep confirms the live selection path reads `duel.verdict.achieved`, never `_spine_confirmed`.

### A2 — Falco-degrade first-class marker + episode exclusion
- **Current:** `start_falco` can return `None` (`live_arms_race_run.py:704`); only the MSF modality
  gets `episode.degraded` (706-713) and `verdict["msf_wired"]` (917). A `Falco=None` yields
  `falco_lines=[]` (890-891) → empty `reads_by_host` → loot flagged (`live_truth.py:152-155`) →
  `achieved=False` (916) with NO marker.
- **Required:** when `falco is None`, append `episode.degraded {"modality_down":"falco", ...}`
  (mirror the MSF block) and set `verdict["falco_wired"]=False`. A syscall-source-absent episode must
  be EXCLUDED from the generation's fitness (dropped from the objective denominator), never scored as
  a red loss.
- **Implement:** add the `if falco is None:` degraded block right after line 704; set
  `verdict["falco_wired"] = falco is not None` next to the `msf_wired` line (917); in the co-evo
  fitness aggregator, skip episodes with `falco_wired` False.
- **Acceptance (cold):** with `start_falco` stubbed to None, the chain carries `episode.degraded
  modality_down=falco` and `verdict.falco_wired=False`, and the aggregator excludes the episode; a
  normal run is byte-unchanged.

### A3 — Runtime witness assertion per range boot
- **Current:** the reconciler is correct GIVEN the witnesses appear, but the unit tests feed the
  "Accepted" auth lines as fixtures (`sensor_real.py` selftest; `live_telemetry.py` fixtures), so
  they cannot catch a range whose sshd logs auth to syslog instead of stdout, or a Falco with a
  mis-mounted docker.sock (`start_falco` comment warns this yields `container.name=<NA>`, filed under
  host `"?"` by `parse_syscall_events:91-94`).
- **Required:** a one-time per-boot check on the live unified range that (a) a known benign sshd
  "Accepted" line surfaces in the destination container's `docker logs`, and (b) a known benign
  file-open surfaces in Falco attributed to its `range-<host>` container (not `"?"`). Fail the boot
  if either is missing; record the check as a system event on the chain.
- **Implement:** a boot-check helper (driver range-standup or `scripts/validation/`) that triggers a
  benign login + a benign read and asserts both appear, attributed, in the telemetry chain within a
  timeout.
- **Acceptance (cold):** the boot-check event re-derives from a committed chain with both witnesses
  present + attributed; CC demonstrates once that the check FAILS on a range built without sshd `-e`
  and on one with docker.sock mis-mounted.

### A4 — Floor line from `reverify_floor` per generation
- **Current:** `arms_race.episode_metrics` sets `oos_executed = 0` as a literal (`arms_race.py:145`);
  `coevolve.py:252` and `:311` consume it for the per-generation floor chart — a number that cannot
  falsify a breach.
- **Required:** the per-generation floor number comes from `reverify_floor` (or `audit_scope`) on the
  committed chain, never the `arms_race` literal.
- **Implement (preferred):** the co-evo driver runs the brief's existing per-generation
  `reverify_floor` hook and reports THAT as the floor; the `arms_race` literal is not used for the
  floor chart. (Alternative: make `episode_metrics` compute oos from `audit_scope` — a non-frozen
  `arms_race.py` change.)
- **Acceptance (cold):** the co-evo floor chart's per-generation oos equals the planner's independent
  `reverify_floor` re-derivation on each committed chain; the `arms_race` literal is confirmed not to
  be the reported source.

### A5 — Map-blind guard covers the memory channel (DATED AMENDMENT; prereq of memory-on)
- **Current:** `assert_red_map_blind` scans only the seeded awareness context
  (`live_agent.py:182+`), not `episodic_recall`. Recall is not wired into the measured engine yet
  (`run_interleaved_duel` → `run_red_agent` is called without `episodic_recall=`), so no live leak
  today.
- **Required:** extend `assert_red_map_blind` (and the `frontier_awareness` assembly) to scan what
  red READS FROM and WRITES TO episodic memory for ground-truth tokens (crown host / path / user,
  scope, topology, oracle output); the selftest must bite on a planted memory entry carrying a GT
  name. Land as a seq-50+ amendment recording the new `live_agent.py` hash.
- **Acceptance (cold):** the extended guard's selftest raises on a planted GT-name memory entry and
  passes on a clean one; the planner re-runs it cold; the amendment chain verifies and the recorded
  hash matches the edited file. This unit must land before the memory-on build unit.

### A6 — Two-auditor agreement (chain-constraint path; no TCB edit)
- **Current:** audit takes the FIRST `floor.boundary` (`audit.py:120`, `shared is None` guard);
  `reverify_floor` takes the LAST (`:109-111`, overwrite loop); audit honors `scope`-event aliases,
  `reverify.canon` (`:48-59`) ignores them. They agree only on single-boundary, alias-free chains
  (verified on all 13 current chains). The audit cross-check selftest is skipped (its data file is
  absent) and still passes.
- **Required (preferred, no TCB edit):** pin co-evolution chains to ONE `floor.boundary` per
  episode-file and NO `scope`-event aliases (a driver convention), and add a non-TCB parity test
  `scripts/validation/auditor_parity.py` that runs BOTH auditors on every committed co-evo chain and
  asserts their oos counts and canonical resolutions agree. This keeps `audit.py` /
  `reverify_floor.py` frozen. (Invasive alternative, only if multi-boundary chains ever become
  necessary: a seq-50+ amendment making both auditors pick the same boundary and both honor aliases.)
- **Acceptance (cold):** `auditor_parity.py` passes on all committed chains and FAILS on a synthetic
  double-boundary chain and on an aliased chain (proving it bites); no frozen file is edited.

---

## GROUP B — before blue acts (observe → act)

### B1 — Prevention gated on real effect
- **Current:** `state["contained"].append(host)` + the spine `confirm`/`mutate` fire on dispatch
  success regardless of `_real` (`live_blue_agent.py:595-603`); `prevented = (not achieved) and
  bool(state["contained"])` (725); feeds MTTC and `blue_score_fitness` `contain_speed` (20%).
- **Required:** gate `state["contained"]`, the prevention effect of the `blue.contain` beat, and the
  spine `mutate` on `_real` (`fidelity=="real"`) or a telemetry-confirmed cessation. A
  simulated/unverified containment is still LOGGED (transparency) but does not set
  contained/prevented.
- **Acceptance (cold):** a dispatched containment returning `fidelity="SIMULATED"` does not append to
  `state["contained"]` and `prevented` stays False; a real one does; the spine `mutate` only fires on
  real. Observe-only arm (the claim-3 erosion signal) unchanged.

### B2 — Eviction ladder routed through `gate.dispatch` + mediation test
- **Current:** `gate.dispatch` appears 0 times in `blue_contain.py`; every primitive calls
  `run_effect` raw (no scope check, no chain record). Only `isolate_host` is wired, mediated by
  caller discipline (`live_blue_agent.py:584`).
- **Required:** wire `remove_foothold`/`rollback_host`/`close_vector` as
  `executors` → `_effect` → `gate.dispatch("blue", ...)`; never call a `blue_contain` primitive
  directly from the duel. Add a mediation test (`scripts/validation/blue_mediation.py`) asserting
  every blue host-affecting effect reaches `run_effect` only via a `gate.dispatch`.
- **Acceptance (cold):** the mediation test passes for the wired ladder and FAILS on a direct
  `blue_contain.rollback_host(...)` call; each wired eviction emits `gate.allow`/`gate.block` and a
  chain record, so `reverify_floor` sees blue's effects.

### B3 — Blue air-gap self-enforced; GT side door closed
- **Current:** the per-tick window calls `assert_label_free` in the DRIVER (`_telemetry_window`), not
  inside `run_interleaved_duel`, so a future co-evo driver that builds its own window and forgets the
  wrapper feeds blue unguarded data. Blue memory exposes `extra={"techniques_seen":[cve]}` (a GT side
  channel); the air-gapped path is near-empty (a `chose` vs `tool` schema mismatch).
- **Required:** `run_interleaved_duel` itself asserts its blue input is label-free + carries no
  red-internal fields (call `assert_label_free` inside the engine on every window); remove the
  `extra=` `techniques_seen` channel from blue memory; fix the `chose`/`tool` schema so the
  air-gapped path carries the real per-tick signal.
- **Acceptance (cold):** a driver passing an unguarded window raises inside `run_interleaved_duel`;
  blue memory contains no cve/technique GT field on a live chain; the air-gapped blue memory path is
  non-empty and label-free.

---

## GROUP C — before red gets a free-form command / shell tool

### C1 — Egress mediation on any free-form red command
- **Current:** `command=` appears 0 times in `live_red.py`; `gate.check_egress` exists but never runs
  on the live path because red's tools take a fixed verb+target.
- **Required:** any new red shell/`run_command` tool passes `command=` to `gate.dispatch` so
  `check_egress` runs. No `gate.py` edit.
- **Acceptance (cold):** a test red command to an OOS target, including decimal / hex / ipv6-mapped
  IP encodings, is blocked by `check_egress` and logged; verified on a chain.

### C2 — Kernel backstop run + in CI  [relayed from Agent 1 — confirm on-machine]
- **Current:** Agent 1 reports `parser_fuzz --selftest` finds 3 IP-encoding bypasses
  (`curl http://2887122948/`, `http://0xac160004/`, `http://[::ffff:172.22.0.4]/`);
  `reachability_probe --selftest` crashes (`docker-compose.yml` absent, generated by
  `topo_to_compose.py --unified`); `make test` runs neither. The planner did NOT re-run these (no
  docker/compose in the cloud container).
- **Required:** fix the compose generation so `reachability_probe --selftest` runs; add `parser_fuzz`
  + `reachability_probe` to `make test`/CI; the kernel segmentation correlation (the compensating
  control for the 3 parser bypasses) must run and pass.
- **Acceptance:** CC runs `parser_fuzz --selftest` on-machine and reports the actual bypass set
  (confirm the 3); `reachability_probe --selftest` runs clean; both are in `make test`. Planner
  verifies the CI wiring and re-reads the probe output.

---

## DECISIONS FOR DANTE (inline, not blocking the build)
- **A6 approach:** recommend the chain-constraint + parity-test path (keeps the auditors frozen).
  Confirm, or say if you want the invasive structural fix instead.
- **D1 — t_loot crown-cred fallback** (`live_red.py:1215-1216`): keep it (co-evolution measures
  "reach the segment and loot") or remove it (measures "harvest + reuse credential tradecraft").
  Your call before the measured arm; not needed to start the build.
- **Amendment batch:** A5 is the one unit here that must be a dated seq-50+ amendment. Recommend
  folding it with the pending app_crown_3hop held-out decision into a single seq-50 amendment when
  you give the go.

## VERIFICATION PROTOCOL (planner half)
For each unit the planner re-derives the acceptance cold from the committed chain / source, trusting
neither CC nor its report. TCB amendments are checked by re-walking the chain and confirming the
recorded hash matches the edited file. Units are verified in A → B → C order; the memory-on,
blue-to-claim-3-spec, Hall-of-Fame, memory-on/off control, transfer-eval, and pathology-falsifier
build units from the co-evolution brief proceed on top of a cleared Group A (and Group B for the
acting-blue arm). Best-of-3 and the oracle layer are untouched and resume on the Nebius top-up.
