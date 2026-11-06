# Readiness-fixes verification log (planner/verifier, 2026-10-29+)

Cold-verification verdicts for the Group A/B/C units in
`2026-10-29-coevolution-readiness-fixes-cc-build-brief.md`. One entry per unit as it lands. Each is
verified against current source re-staged fresh, trusting neither CC nor its selftest: I read the
shipped bodies, re-derive the logic, and run the pure parts cold where I can. A unit clears only when
its brief acceptance re-derives independently.

---

## A1 — selection keyed on the telemetry-gated verdict — CLEARS (verified cold)

**What CC shipped** (swarm/population.py + swarm/coevolve.py, both re-staged at tonight's mtimes):
- `gated_objective(events)` (population.py:257-270): reads the red objective term ONLY from the
  `duel.verdict` event on the chain (written by `live_arms_race_run._corroborated_objective`), returns
  1.0 iff `achieved`, and RAISES if no reconciler verdict is present. Never touches `_spine_confirmed`.
- `live_red_score_fitness(events, gt)` (population.py:273-280): `score_fitness(events, gt,
  objective=gated_objective(events))` — identical shaping (depth/technique/exploit/stealth/manip), but
  the objective term is the gated verdict.
- `score_fitness` gained an injected `objective` param (population.py:203, 236-240): `objective=None`
  keeps the old spine-read path byte-identical (dry/offline shaping); a passed value is used instead.
- Side wiring: `SIDES["red_live"].score_fitness is live_red_score_fitness`; `SIDES["red"]` keeps
  `score_fitness`. `Evolver(side=...)._score = spec.score_fitness` (population.py:583-585) and
  selection reads `self._score(events, gt)` (:626). So an `Evolver(side="red_live")` selects on the
  gated objective; `coevolve.run_coevolution(red_side="red_live")` is the live path, `"red"` the dry
  self-check.

**How I verified (cold):**
- Re-derived every body by hand from the shipped source.
- Ran the keystone `gated_objective` VERBATIM on the brief's acceptance fixtures in an isolated
  script: a flagged chain (crown.access + exfil mutate present, `duel.verdict.achieved=False`) →
  **0.0, not 1.0**; a witnessed chain (`achieved=True`) → 1.0; a chain with no `duel.verdict` →
  **RAISES**. Pass.
- Confirmed the `objective=0.0` edge: `score_fitness`'s branch is `if objective is None`, so a live
  0.0 is treated as injected, not falsy-fallback to the spine read. Correct.
- Confirmed `_spine_confirmed` is reached only on the `objective=None` (dry) branch and in
  `blue_score_fitness` (blue's own term), never on the live red path.

**Meets the brief's A1 acceptance** (flagged chain → objective 0.0; live path reads
`duel.verdict.achieved`, never `_spine_confirmed`), and exceeds it: the no-fallback protection is a
hard RAISE in `gated_objective`, not just a driver assertion, so the live red fitness cannot be
computed on an unreconciled duel.

**One hardening to apply when the live generational loop is built (not an A1 defect).** The
no-fallback guarantee currently holds *because* the live loop uses `side="red_live"`. If a future
wiring instantiated the live duel under `side="red"` by mistake, `score_fitness(objective=None)` would
silently score the fidelity-blind spine objective again — the exact thing A1 removes. Cheap, decisive
fix: in `score_fitness`, when `objective is None` AND a `duel.verdict` is present in `events`, RAISE
(a reconciled/live chain must use the gated term). Dry chains carry no `duel.verdict`, so they stay
byte-identical. This makes the guarantee independent of which side the loop wires. Recommended for the
live-loop unit.

**One watch-item for the blue arm (B-group, not A1).** `blue_score_fitness` (population.py:390-401)
still reads `_spine_confirmed` for its objective context, so blue could be scored against a red "win"
the telemetry did not witness. When the acting-blue arm lands (B1 and the blue fitness), move blue's
objective term onto the gated verdict too.

**Verdict: A1 clears.** The live/measured red can only select on a telemetry-witnessed win, and a
fabricated or unwitnessed crown read scores zero on the objective term.

---

## A2 — Falco-degrade first-class marker + episode exclusion — CLEARS (verified cold)

**Change set (exactly three non-frozen files, confirmed by mtime; frozen TCB byte-stable):**
`scripts/live_arms_race_run.py`, `swarm/population.py`, `swarm/coevolve.py`. Frozen files all predate
tonight's work: gate/eventlog/spine/audit (swarm), `redteam/reverify_floor.py` (1792866676158),
`scripts/mediation/static_coverage.py` (1793266706054). No other file carries an A2-window mtime.

**What CC shipped:**
- `live_arms_race_run._mark_degraded_modalities(log, *, msf, falco)` (691-710): appends a first-class
  `episode.degraded` marker for each down modality (`modality_down="msf"` when msf is None,
  `modality_down="falco"` when falco is None) and returns `{msf_wired, falco_wired}`. The old inline
  MSF block is gone, both markers live in this one place (honors "no second copy"). Called at :732;
  the verdict folds the flags in at :938 via `verdict.update(_modality_wired)` — additive, does not
  touch `achieved`.
- `population.falco_degraded(events)` (283+): re-derives the falco-down state from the chain
  (`episode.degraded modality_down=="falco"`, or `duel.verdict.falco_wired is False`).
- `population.SideSpec.exclude_episode` (445, default None) + `Evolver._exclude` (607): in `tick`,
  the genome's events are appended to `last_gen_events` (:643) and THEN, if the predicate flags them,
  the episode is dropped before scoring (`gen_excluded += 1; continue`, :651-653). `SIDES["red_live"]`
  wires `exclude_episode=falco_degraded` (:458); dry sides leave it None (byte-identical).
- `coevolve.py` A2 change is an added selftest (373-407) only; no new production logic.

**How I verified (cold):**
- Ran `falco_degraded` VERBATIM: a falco-down chain → True, a normal chain → False.
- Ran the exclusion-ORDER property modeling `Evolver.tick`: the degraded episode is dropped from
  fitness (`excluded==1`, never scored) yet its events remain in `last_gen_events`, so the floor
  invariant still covers it. This is the subtle correctness point and it holds.
- Read `_mark_degraded_modalities` + call site + verdict fold: falco=None → `episode.degraded
  modality_down=falco` + `falco_wired=False`; both up → no marker, both wired True (normal run
  byte-unchanged); the flag is additive and `achieved` is unchanged.

**Meets the brief's A2 acceptance:** falco=None emits the degraded marker and `falco_wired=False`; the
aggregator excludes the episode (never a red loss); a normal/dry run is byte-unchanged. Correct design
call: only falco (not msf) triggers fitness exclusion, because a falco-down loot cannot be witnessed
at all, whereas msf-down red can still foothold via other paths.

**Two notes (neither an A2 defect):**
- Not independently run from here: `make test exit 0` (no repo/deps in the cloud container). The
  specific A2 acceptance logic I executed cold passes; the full suite is CC's claim.
- Live-loop robustness edge for later: if an entire generation is falco-down, every episode is
  excluded and the generation produces no fitness/archive entries. Handle an all-excluded generation
  gracefully (retry or surface it) when the live generational loop is built.

**Verdict: A2 clears.** A Falco outage can no longer be silently scored as a red loss; it is a
first-class, re-derivable degraded marker and the episode is dropped from fitness while still counting
for the floor.

---

## A3 — per-boot runtime witness assertion — CLEARS (verified cold)

**Change set:** one new file, `scripts/validation/boot_witness.py` (plus one Makefile line to put its
selftest in `make test`). No other validation file moved; frozen TCB untouched. The Makefile is not
frozen TCB.

**What CC shipped:**
- `witness_verdict(host, dst_logs, falco_lines, benign_file)` — the pure core. Auth witness: the real
  `sensor_real.SIGMA_RULES` T1021 "Accepted" regex pulled directly (`_AUTH_RX`, not a second copy).
  Syscall witness: `live_telemetry.parse_syscall_events` (the real parser), requiring at least one
  event attributed to `range-<host>` (not `"?"`), and mentioning the benign file. Reports
  total/attributed/unattributed so a failure localizes (total>0, attributed==0 = docker.sock
  mis-mount).
- `run_boot_witness(log, host, *, trigger, capture, ...)` — triggers the benign login+read, captures
  (`capture_boot_telemetry` reuses `tail_logs`/`read_falco`), records `boot.witness_check` on the
  chain EITHER WAY, and raises to fail the boot if either witness is missing. trigger/capture injected.

**How I verified (cold):** ran `witness_verdict` with the real parser logic inlined on three fixtures.
Healthy → ok, one attributed syscall. No sshd `-e` (no "Accepted" in docker logs) → auth witness
False → boot fails. docker.sock mis-mount → I confirmed the real parser files `container=<NA>` under
`"?"` (the `container=([A-Za-z0-9_.\-]+)` class excludes `<`/`>`), so attributed==0 → syscall witness
False → boot fails, even though Falco emitted output. The crucial property holds: the check reuses the
real parsers, so it reads telemetry exactly as the reconciler does and cannot pass while the reconciler
would flag.

**Meets the brief's A3 acceptance:** both witnesses checked live, boot fails if either is missing, the
verdict recorded on the chain for cold re-derivation.

**Caveats (important, not defects):**
- **Built and correct, but not yet wired into a live standup.** A3 delivers the check as a validator +
  driver-callable; the actual call at range boot is deferred to the live-loop unit (it needs the live
  range's real ssh user / IP / canary path). The docstring pins the exact call site. Until that
  one-line wiring lands, the per-boot guarantee is not active in a live run. Track it as a required
  part of the live-loop unit, not an optional extra.
- **FAIL demos are on fixtures, not actually-booted broken ranges.** The fixtures are faithful (the
  real parsers process them), so the logic is proven. A live demonstration on real broken ranges is
  free (Docker, no Nebius spend) and would add assurance that a real broken range emits exactly that
  telemetry; it is optional and is Dante's call (CC did not fire it).

**Verdict: A3 clears.** The mechanism that fails a boot when the lateral or crown-read witness is not
surfacing live is built and correct; its live wiring is a tracked follow-up for the live-loop unit.

---

## A4 — per-generation floor line sourced from reverify_floor — CLEARS (verified cold, real auditor)

**Change set:** only `swarm/coevolve.py` (+4.9KB). `arms_race.py` (1792828571630) and frozen
`reverify_floor.py` (1792866676158) are both untouched, confirmed by mtime — the preferred
no-TCB-edit path. Frozen TCB clean.

**What CC shipped (all in coevolve.py):**
- `_dry_scope(objective_host)` — one source of truth for the dry range's scope
  (`in:[struts,db,objective_host], out:[oos_decoy]`), used by both `dry_duel` (byte-identical to the
  old hardcoded `in_scope`) and the floor chain's `scope` event.
- `_write_generation_chain(path, objective_host, events)` — writes a committed hash-chained chain:
  a `scope` event from `_dry_scope` (the RANGE DEFINITION), then the episode events.
- `_reverify_floor(path)` — delegates to `redteam/reverify_floor.reverify` (the independent auditor
  that imports neither the gate nor swarm.audit).
- `coevolve_populations` reports `oos_executed` from `_reverify_floor` on the committed gen chain,
  history carries `floor_source="reverify_floor"` + `floor_chain`, `gate_flat_zero` computed from it.
  The `arms_race.episode_metrics` literal is gone from the floor path.

**Non-circularity (the crux) — verified by reading:** the `scope` event is sourced from `_dry_scope`
(the range definition), NOT from red's own `gate.allow` targets. So a `gate.allow` to a host outside
`{struts,db,objective_host}` is a real miss; it cannot be excused by red having targeted it. The
docstring states this intent and the code implements it.

**How I verified (cold, with the REAL frozen primitives):** I staged the actual `swarm.eventlog` and
`redteam/reverify_floor`, wrote two chains exactly as `_write_generation_chain` does, and ran the real
`reverify_floor` on them:
- in-scope chain (gate.allow to `db` + the oos probe the gate BLOCKS) → `chain_verified=True`,
  `oos_executed=0`.
- breach chain (+ a gate.allow to `oos_decoy`, out of scope, executed) → `chain_verified=True`,
  `oos_executed=1`.
So the floor number is a real, falsifiable re-derivation by the independent auditor, not the
`arms_race` literal (which the selftest confirms still reports 0 on the same breach — exactly why it
must not be the source).

**Meets the brief's A4 acceptance:** per-generation `oos_executed` equals an independent
`reverify_floor` re-derivation on the committed chain; the floor can falsify a breach; the chain is
left on disk so an external auditor re-derives the same number. `make test exit 0` is CC's claim (not
run from here); the floor acceptance I ran with the real auditor passes.

**Verdict: A4 clears.** The co-evolution floor line is now a number an external party re-derives cold
from the committed chain, with scope sourced non-circularly from the range definition, and it catches
an out-of-scope execution that the old literal could not.

---

## A5 — GT firewall extended to the episodic-memory channel — CLEARS (verified cold); SEQ50 anchor pending

**Change set:** only `swarm/live_agent.py` (the one pinned/frozen-TCB edit, pre-registered by SEQ50
Part 2). Post-edit SHA256 (computed by the planner from a fresh stage):
`bc8273131278254eca5129535d59fada9c1fe3da696f318b897ef2b72213c29a` (63667 bytes).

**What CC shipped:**
- `assert_red_map_blind` gains `episodic_recall` (the memory READ, folded into the scanned prompt
  byte-identically to `run_red_agent`'s fold — compared lines 229-230 vs 562-564) and `memory_write`
  (the lesson red persists, flattened via `_stringify_memory` so a GT name nested in a structured
  entry is caught). Both, plus the awareness-text assembly, are scanned for `_map_tokens`; any leak
  raises.
- `_map_tokens` extended to the SEQ50 Part 2 token classes: scope (`in_scope`/`out_of_scope`) and the
  oracle output (`cred_seam.chain`), alongside the existing crown/credential/host tokens. IPs are
  intentionally excluded (red may discover IPs; names/scope/chain are the map).

**How I verified (cold):** replicated `_map_tokens` (the A5-new scope + `cred_seam.chain` classes),
`_stringify_memory` (verbatim), and the leak check (verbatim) and ran the selftest's fixtures: a clean
general-tradecraft recall + write PASSES (adds no GT to red's context); a `cred_seam`-chain host in
recall LEAKS (caught `db-bastion, db-core, web01`); a nested memory write naming a GT host LEAKS; a GT
name in the awareness assembly LEAKS. Meets the brief's A5 acceptance.

**Anchor status (pre-registration, SEQ50):** verified cold against the mechanism.
`scripts/preregister.py` hashes a fixed artifact list and appends an amendment for whatever changed.
`swarm/live_agent.py` is pinned there (since seq-47); the A1-A4 files (`population.py`, `coevolve.py`,
`live_arms_race_run.py`, `scripts/validation/boot_witness.py`) are NOT pinned, which is why they
correctly needed no amendment. The planner confirmed cold: the prereg chain verifies (50 events, last
prereg seq-49), and the last anchor's recorded `live_agent.py` hash (`fb92cb8c…`) differs from the
post-A5 hash (`bc8273…`) — the drift the amendment must capture. So the "seq-50" amendment is exactly
the `live_agent.py` (A5) change. The app_crown_3hop replacement (SEQ50 Part 1) and the D1 fallback
removal (Part 3) are NOT ready; they anchor as their own later amendments when their artifacts change
(`docs/held-out/.../ground_truth.json`; the measured-arm prereg). The three-part "batch" was a
planning convenience; `preregister.py` anchors per artifact-change, so they separate naturally.

**Anchor procedure (Dante's step — the planner cannot run tools on the device over the file-only
bridge):** run `.venv/bin/python scripts/preregister.py` (it detects live_agent.py changed, appends
the seq-50 `prereg.amendment` with the new hash set, and verifies the chain), then commit (author
drcano). The planner then stages the new `prereg.jsonl` and verifies cold that the chain extends to
seq-50 and the recorded `live_agent.py` hash equals `bc8273…`.

**Verdict: A5 clears (code verified cold).**

**SEQ50 anchor — VERIFIED (2026-10-30).** Dante ran `preregister.py` and committed (104721e). The
planner re-staged `prereg.jsonl` and verified cold: the chain extends to **seq-50**
(`prereg.amendment`, git_head 8cecbb15, registered_on 2026-10-30), and the recorded
`swarm/live_agent.py` hash is **`bc8273131278254eca5129535d59fada9c1fe3da696f318b897ef2b72213c29a`**,
equal to the planner's post-A5 computation. The frozen-file edit is hash-anchored and matches the
verified file. (SEQ50 Part 1 app_crown replacement and Part 3 D1 remain unanchored — separate later
amendments when their artifacts change.)

---

## A6 — two-auditor parity (no TCB edit) — CLEARS (verified cold, real auditors)

**Change set:** new `scripts/validation/auditor_parity.py` + a write-time convention guard in
`swarm/coevolve.py` (`_write_generation_chain` asserts episode events carry no
scope/floor.boundary/aliases) + one Makefile line. `audit.py` (mtime unchanged) and
`reverify_floor.py` are only READ — frozen TCB untouched. (A6 built but uncommitted; Dante commits it
as its own commit.)

**What CC shipped:** `parity(path)` runs BOTH `audit.audit_scope` and `reverify_floor.reverify` and
requires they agree on the oos count, the derived scope, and the flagged-canonical set, plus the
convention (one boundary source, alias-free). It targets the exact seams: audit reads the FIRST
`floor.boundary` and honors `scope` aliases; reverify reads the LAST and ignores them.

**How I verified (cold, with the REAL two auditors):** built three chains with the real `EventLog` and
ran the real `parity`: a clean single-boundary/alias-free chain → AGREE (both oos 0); a double-boundary
chain → `audit_oos=0` vs `reverify_oos=1`, parity FAILS (bites); an aliased chain (audit honors,
reverify ignores) → `audit_oos=0` vs `reverify_oos=1`, parity FAILS (bites). This empirically
reproduces Agent 1 #4's divergence and confirms the test catches it. The coevolve write-time guard
keeps co-evo chains on the convention so they can't drift into the ambiguous shape.

**Verdict: A6 clears.** The two code-independent auditors are now held to agreement on every co-evo
chain by a non-TCB test plus a source-enforced convention, keeping both auditors frozen.

---

## GROUP A — CLEARED (the gate before any co-evolution generation)

All six readiness fixes are built and verified cold; the one frozen edit (A5) is anchored (seq-50).
- A1 fitness keyed on the telemetry-gated verdict — committed (104721e).
- A2 Falco-degrade marker + fitness exclusion — committed.
- A3 per-boot witness assertion — committed; **its live-boot call-site wiring is deferred to the
  live-loop unit** (the check exists and is correct, but is not yet invoked at a real boot, so the
  per-boot guarantee is not active in a live run until then).
- A4 floor line from reverify_floor — committed.
- A5 map-blind-memory guard — committed + seq-50 anchored.
- A6 auditor parity — verified, pending its own commit.

**What "Group A cleared" does and does not mean.** The INSTRUMENT is now ready for co-evolution: a
live/measured generation cannot select on a fabricated win (A1), be penalized for a dead sensor (A2),
trust telemetry that is not surfacing (A3), draw a floor number that cannot falsify a breach (A4),
leak the map through memory (A5), or rest on auditors that silently disagree (A6). It does NOT mean a
co-evolution generation can run yet: the live generational loop (select → mutate → re-run around
`run_interleaved_duel`) is still unbuilt, and when it is built it must incorporate (i) A3's boot
call-site, (ii) the A1 side-wiring hardening (score_fitness should refuse the spine objective when a
`duel.verdict` is present, so the guarantee is independent of which side the loop instantiates), and
(iii) an all-excluded-generation guard (A2 edge). Group B (before blue acts), Group C (before red's
free-form command tool), the SEQ50 Part 1 (app_crown replacement) + Part 3 (D1) anchors, and the
memory-on / measured-arm units are the follow-on work. No paid run until Dante's explicit go.
