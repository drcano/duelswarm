# CC brief — the live arms race: populate → contest → co-evolve (2026-10-28)

The instrument is validated (one engine, floor cold `oos_executed=0`, reconciler honest through seq 38,
capable-red non-degenerate clean seed verified at source). This brief takes the sandbox from a verified
instrument to the two-sided, populated, co-evolving arms race the thesis needs. Three phases, in order;
each FREE-dry-verified before any paid measurement; paid runs GATED on Dante's explicit go.

Reviewed reorder (from the source + Dante's own `2026-10-27-stealth-vs-detection-benign-baseline.md`):
**the benign baseline is the enabler, not a later step.** Activating blue on the current empty,
loud-only range is a foregone conclusion (blue alerts on the only event that ever happens), not a
result. So benign + least-privilege topology come FIRST; "activate blue" folds into the contest in
Phase 2.

## Rails (every phase, non-negotiable)
- Instrument FROZEN: `gate`/`eventlog`/`spine`/`audit`/`reverify_floor`/`static_coverage`. Benign lives
  in the range generator; quiet entry + evasion in red; discrimination in blue. The gate/chain/auditors
  do not move.
- Red MAP-BLIND (holds a cred, never the crown location / graph / scope). Blue LABEL-FREE (benign vs
  malicious labels are ground-truth for SCORING only, never in blue's view — the mirror of map-blindness).
- The floor is invariant and ordering-independent: `oos_executed=0`, chain verify, §E host-egress — it
  re-derives COLD on every seed REGARDLESS of the stealth/contain outcome. Turning blue on and adding
  benign noise must never touch the floor. If a phase moves the floor reading, STOP and report.
- Pre-register BEFORE measuring (no tuning to manufacture a race); nulls kept in; dated hash-anchored
  amendments (prereg seq 39+) for any registered-apparatus or topology change. `make test` green;
  `prove_one_engine` still one-of-each after every phase. Nebius-only counted; author
  `Dante Cano <drcano@ucsd.edu>`; `real-range`; NOTHING pushed.
- Output discipline: every produced statement is re-derivable cold, scoped to a guarantee, or labeled
  pending; load-bearing results witnessed by the kernel / a mechanical checker, never Dante+CC+Claude alone.

---

## PHASE 1 — Populate the range: benign baseline + least-privilege topology on the LIVE engine
**Goal.** The one live engine generates the least-privilege segmented range `benign_baseline` models AND
emits deterministic-per-seed legitimate activity as REAL telemetry on the hash-chained chain, label-free
to blue — so a single login/connection is not uniquely attacker.

**What already exists (wire/rewrite, don't rebuild).** `swarm/benign_baseline.py` — the least-priv
topology model (db-core reached legitimately only by a NARROW admin path; `dba01/dba02/etl01/bkupctl`
reach Tier-1; the rest have NO legitimate route to the data tier) + the benign-activity model
(`benign_schedule`/`benign_window`/`warmup_schedule`/`legit_adjacency`/`benign_hosts`/`stealth_entry_for_seed`/
`STEALTH_SEEDS`). `live_blue_agent`'s duel fn already ACCEPTS `benign_window`/`discriminator`/
`benign_hosts` (it just isn't passed them live). Proven offline in `scripts/prove_stealth_setup.py`.

**The gap (verified at source).** `scripts/live_arms_race_run.py` has NO benign path; the live range
generator (`topo_to_compose.generate_unified`) is over-permissive and does NOT match `benign_baseline`'s
least-priv topology. The full stealth setup runs only in the proof harness.

**Build.**
1. **Reconcile the topology — this is the spine.** The range red actually breaches must BE the
   least-privilege topology `benign_baseline` describes: same hosts, same adjacency, the ONE legitimate
   edge into the data tier. Make it a single source of truth (the generator derives from, or shares,
   `benign_baseline`'s topology) so the benign story and the breach story cannot disagree. A host with
   no legitimate route must be unable to legitimately reach db-core on the generated range.
2. **Emit benign activity live.** Each tick/episode the range emits `benign_baseline`'s scheduled
   activity (admin SSH logins, service-to-service connections, routine process/syscall activity) into the
   SAME hash-chained telemetry chain the reconciler reads — same telemetry classes red uses — labeled
   benign in ground-truth ONLY.
3. **Feed blue on the live path.** Pass `benign_window` + a pre-registered discriminator + `benign_hosts`
   into `live_blue_agent` in the live engine (the params it already takes).

**Done-check (FREE, re-derivable cold).** An observe-only live episode shows: benign telemetry events
present in the chain and the chain still VERIFIED; `live_blue_agent` output carries `benign_baseline: true`;
`assert_benign_label_free` holds on the live inputs; the generated range is least-priv (assert from the
compose/topology that a no-route host cannot reach db-core); and the floor STILL re-derives cold
(`oos_executed=0`, chain verify, §E). Pre-register the benign model + topology (amendment, hash-anchored)
before any counted run.

**Bonus it unlocks.** A least-priv range is the exact terrain for the composition-migration claim (red
landing with no legit route must COMPOSE a chain through the narrow admin path / seams to reach the
crown) — see Phase 2.5.

---

## PHASE 2 — The two-sided contest: quiet red + active blue
**Goal.** A pre-registered stealth-vs-detection measurement over N seeds, reported as a triple —
stealth-success / detection / false-positive — with the floor invariant and cold on every seed.

**What already exists.** Active containment: `_real_contain` (real `docker network disconnect` + OOB
re-inspection via `swarm.blue_contain`) and the `blue_observe_only` flag. Discriminating blue
(behavioral, label-free, with a false-positive cost: containing a benign host = measured damage). Proven
offline in `scripts/prove_stealth_detection.py`.

**Build.**
1. **Quiet / assumed-breach red on the LIVE path (closes C2).** Add red's quiet IDENTITY as a live
   dimension: enter from a valid low-priv credential (T1078, models initial access already achieved), move
   laterally by credential-reuse / valid logins (T1021/T1078) and living-off-the-land, so red's actions
   resemble benign admin traffic. Map-blind as ever; objective unchanged (reach db-core, exfil the real
   PII) but now it must BLEND. Keep the loud MSF arsenal as a SEPARATE red identity (loud vs quiet is the
   dimension — do not replace loud); tag the identity on the chain so a log reader sees which ran.
2. **Activate blue (a flip + a witness).** Run `blue_observe_only=False` with `_real_contain`; verify it
   grounds a REAL `contained` confirm (OOB re-inspection, zero simulation) and that containing a benign
   host registers as measured false-positive damage.
3. **Measure.** Pre-register red's evasion repertoire + blue's detector logic + threshold BEFORE
   measuring. Run N seeds; per seed report the triple AND the floor reading. No tuning either side to
   manufacture a race — "stealthy red evades X/N" and "blue catches it" are equally valid results.

**Done-check.** FREE first: a dry run shows both red identities available, active containment grounding a
real docker-disconnect confirm, and a benign containment scoring an FP. THEN the paid N-seed run (GATED on
Dante): each seed re-derives cold — floor `oos_executed=0` + chain verify; the triple computed from the
chain + ground-truth labels; the reconciler honest on red's claims.

**Guardrail (D2).** Detection is NOT the headline. Stealth/detection serves the selection and
informational-asymmetry claims (1 & 3); the composition claim (2) is red-vs-floor and needs no blue. Report
the floor invariance as the spine and detection as supporting evidence, never as the result.

### PHASE 2.5 (optional, red-vs-floor, no blue) — the composition-migration experiment
On the Phase-1 least-priv range: vary the floor SHAPE (which edges/seams the gate permits) across
pre-registered configurations and measure where red's SUCCESSFUL path goes — does tightening one seam push
the achieved chain to another, while `oos_executed` stays 0 throughout? This is the most novel thesis
contribution and Phase 1 is its only prerequisite; it can run in parallel with Phase 2. Pre-register the
floor-shape configs; report the migration of the achieved path with the floor cold on every config.

---

## PHASE 3 — Co-evolution on the one live engine
**Goal.** Genuine cross-generation co-evolution on the LIVE path: red's memory/evasion evolves, blue
refits its discriminator on the red behavior it legitimately observed each generation — not the separate
offline rig.

**What already exists / the gap.** `coevolve.py`/`population.py`/`env_coevo.py`/`instrument.run_coevolution`
exist but are the OFFLINE path — `coevolve` is never imported by `live_arms_race_run.py`. `red_memory.json`
already persists per-seed worked/blocked/caught; the MAP-elites `arsenal_archive` exists. So the build is
WIRING genuine co-evolution around the one live engine, not inventing it.

**Build.**
1. Wrap the generational loop around `live_arms_race_run` (one engine — `prove_one_engine` must still read
   one-of-each; coevolve WRAPS the engine, never forks it). Each generation runs live episodes; red carries
   memory forward (what landed/failed, which evasions beat blue); blue refits its discriminator on the red
   behaviors it legitimately observed (label-free).
2. The (now honest, verified) degeneracy detector gates each generation — a degenerate generation is
   FLAGGED, never counted; novelty/`provenance_hash` markers carry forward.
3. Pre-register the protocol (generations, population, selection, what carries forward) before any counted run.

**Done-check.** FREE: a dry multi-generation run (offline/`--no-llm` tier) shows memory carried forward +
blue refit between generations, the engine still one-of-each, floor cold each generation. THEN the paid
generational run (GATED on Dante). Honest co-evolution REQUIRES Phases 1–2 (a populated range + a two-sided
contest); running it against an empty world would not be co-evolution.

---

## Sequencing
1 → 2 (+ 2.5 in parallel) → 3. Free-dry-verify and report at the end of each phase; HOLD for Dante's
explicit go before any paid measurement. Pre-register (hash-anchored amendment) before each counted run.
`make test` green, `prove_one_engine` one-of-each, floor cold, instrument untouched after every phase.
Nothing pushed. We are close — keep each step airtight and re-derivable, no theater.
