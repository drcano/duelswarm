# Session review — one-engine cut, arsenal live, first measured runs (2026-10-27 → 28)

What we did this session, what the range measured, where we are against the mandate, and every next
step we discussed. Grounded; commits and re-derivation noted. Epistemic frame held throughout:
`oos_executed` is MEASURED not targeted; a penetration is a RESULT; the only build failure is an
unrecorded / non-re-derivable effect; `make test` green is a smoke check, never the done-signal.

## 1. What we built (the convergence + the arsenal) — committed on `real-range`, nothing pushed

| commit | what |
|---|---|
| `7076a00` | one-engine cut steps 1–3: absorb the drivers into the one engine, fold 10 milestone proofs into `scripts/prove_engine.py`, rebuild `make test` |
| `ea3bbfe` | step 3a: re-point the FROZEN `static_coverage` + `leak_test` onto the agent closures (data-only, non-vacuous) before deletion |
| `1429fff` | step 4: delete the ~38-file parallel-engine sprawl; extend `prove_one_engine` (one-of-each + engines-gone); strip viz; CI → `make test`; trim prereg |
| `8715a91` | close the audit: relocate `image_internal_port` (a cut-introduced lazy-import defect); per-entry guarded `corpus_floor` exclusion |
| `b4caf3d` | arsenal increment 1: `ArsenalDriver` + `UnifiedAdapter`; rewrite `build_agent_tools` (real recon → red infers its own CVE → fires a weapon); retire the stub fingerprint + cred-only exploit; non-vacuous dry-verify |
| `4e1cea9` | arsenal increment 2: collapse `live_frontier_executors` onto the ONE `ArsenalDriver` (no parallel universes) + `FrontierAdapter` + a frontier dry-test + the live `vector_planner` activation |

Highlights of the cut: five parallel engines collapsed to **one red loop, one blue, one range, one
measurement duel** (asserted by `prove_one_engine`); the cheat-sheet lineage gone; the instrument
frozen. Two findings the cut surfaced and we fixed honestly rather than papered over: (a) moving
effect sites into swarm-core made the mediation oracle bite — we routed them through the one effect
path (`run_effect`); (b) `D1` was empirically **refuted** — `sensor_stack` is KEPT because `sensor_real`
has no T1071/C2 detector. The `corpus_floor` red was a pre-existing stale-IP artifact on a discarded
run (not an escape), now handled by a per-entry guard that can't launder a real escape.

## 2. What the live runs measured (first capable-red-vs-blue data)

Designed-path fresh unified range each time (real Struts entry, real Samba AD DC, §E firewall verified
closed, AD provisioner applied) — the whole boot driven by CC (the §E firewall runs via `sudo -n`, a
NOPASSWD line; it was never a human step).

- **Run A (blue active) — the arsenal is LIVE-proven.** Red did the real loop: recon → inferred the
  Struts CVE itself → fired a real weapon → grounded a real foothold on `dmz-web`, **reconciler-
  corroborated** against 1,012 telemetry events. Blue detected + contained the entry. Floor cold
  `oos_executed=0`, chain verified. Red earned the foothold with a weapon it chose — not a handed exploit.
- **Run B (blue observe-only, unopposed) — red does NOT complete the objective.** With blue removed and
  all 40 turns, red footholded the entry and then **couldn't progress**: 7 `lateral_failed`, 10/31 turns
  flailing on `author_tool`, no `crown.access`. It *claimed* a lateral + exfil to `db-core`; the
  **reconciler flagged 2 of 3 claims** (not witnessed by 18,311 telemetry events) — the instrument
  **refused to credit red's fabricated progress.** Floor cold `oos_executed=0`.

Reading: the earlier "blue out-paces red" impression was half artifact — unopposed, red still can't
exfil, so the bottleneck is **red**, and the instrument surfaced it honestly.

## 3. Root cause of the failed kill chain (diagnosed at source — two wiring bugs)

1. **(primary) Harvested creds never reach the pivot.** `ArsenalDriver.fire_lateral` → `cred_pivot`
   uses `build_agent_tools`' STATIC defaults (`login_user="dbadmin"`, `key_path="/root/.ssh/id_ed25519"`),
   not what red harvested → wrong user + wrong key → `Permission denied (publickey)`. The harvest→reuse
   linkage is DRY-proven (the `prove_engine` loot-reuse fold) but was never wired onto the live path.
2. **The planted cred is invisible to the harvester.** The plaintext DB cred is mounted at
   `/etc/app/dbconfig.ini` as `db_cred=...`, but `enumerate_and_harvest` greps `password|secret|
   credential|apikey` — `db_cred` doesn't match `credential`, so the harvest misses it.

Red's flailing + the hallucinated db-core claim are downstream of these.

## 4. Where we are vs the mandate (the 7-phase map)

- **Phases 1–3.5 — done.** One engine, cheat-sheet gone, belief folded as awareness (objective-blind
  preserved), tool-authoring on the one effect path, Sliver `prove_sliver_c2` kept. Arsenal = Phase 2's
  "full toolkit," now live-proven at the entry.
- **Range (Phase 5) — substantially done.** One MHBench-sourced generator (`topo_to_compose`;
  `range_gen`/`live_terrain` retired), real exploitable entry + real AD tier, vetted boot-clean images,
  floor re-derivable. Residual is realism breadth (below).
- **Phase 4 — partial.** One effect path enforced; the read-vs-mutate **verb axis** (invariant #3) is
  not built yet.
- **Phase 6 (the real remaining BUILD) — scaffolding only.** Red-pop + blue-pop MAP-Elites machinery,
  personas, archives, and the series spine exist, but drive a *model*, not real duels on the live engine.

## 5. Next steps (everything we discussed, ordered)

**Pre-Phase-6 (make the duel real before co-evolving it):**
1. **Fix the live credential chain** (the two bugs above): feed the harvested key/password into
   `cred_pivot` per target (make the dry loot-reuse real on the live engine); broaden the harvest to
   find `db_cred` + verify the next-hop SSH key is planted/readable. Re-run observe-only and show red
   completing the chain (or failing honestly, re-derivable either way).
2. **Wire the benign baseline into the live duel.** Today detection is a trip-wire (blue reads only
   red's activity → alerts on the first move — "no digital Paul Revere"). `benign_baseline.py` exists
   and the blue engine has a discriminator, but only in the DRY stealth experiment. Run constant benign
   activity on the live range feeding the same telemetry blue reads, so red can hide in a base rate and
   blue must discriminate with real FP cost. **Prerequisite for meaningful Phase 6** (co-evolution
   against a trip-wire has no gradient).
3. **Curb red's `author_tool` flail** (prompt + turn mechanics) — largely downstream of (1).

**Phase 6 — the build (best started as a fresh session):**
4. Red AND blue as co-evolving populations on the ONE live engine: wire `evaluate()` to a real duel on
   `run_interleaved_duel`; give blue a TELEMETRY-sourced fitness (`sensor_stack` recall, dwell/MTTC,
   crown held/lost — never a self-report); build the two-archive loop on the `arms_series` spine; fix
   the confirmation-bias leaks (#4: `manipulation_score` off `red.deception.summary`; `score_fitness`
   off the dead cascade vocabulary onto spine events). Extend the genome to include authored tools.
   Deliverable = the reflexivity curve (does evasion move under a real adapting opponent).

**Realism knobs (additive, deliberate):**
5. Scale the range (~8 → a realistic 20–40+ host enterprise); mixed terrain (more real-vuln inner
   service images so some inner hops are weapon-exploitable, not only credential); real Sliver C2 on the
   wire (today it's the honest `docker-exec` demo-equivalent); the Phase-4 verb axis.

**In flight / housekeeping:**
6. The validating-chat report (`docs/design-log/2026-10-27-arsenal-live-run-report.md`) — drafted,
   uncommitted; Dante editing before it goes out.
7. A fresh pre-registration when the sandbox is built (the prereg manifest was trimmed of the deleted
   decision-rig; a clean re-anchor is deferred).

## 6. State / handoff
- All code committed through `4e1cea9` on `real-range`; **nothing pushed**. Working tree holds only the
  two uncommitted design-log docs (this review + the validating-chat report).
- The unified range is up, freshly designed-booted and verified (§E closed, AD provisioned), instrument
  re-derives clean — ready for the credential-chain re-run.
- Memories written so a fresh session starts informed: `arsenal-live-proven`, `red-killchain-bottleneck`
  (with the root cause), `benign-telemetry-live-duel-gap`, `d1-sensor-stack-kept`,
  `corpus-floor-confounded-run` (resolved), and updates to `real-range-build-gated-live` (live runs
  authorized) + `live-run-preconditions-this-host` (§E is CC-runnable, never a human step).
- Honest scope reminder: the live runs are single episodes, one seed, red homogenized — capable-red-vs-
  blue datapoints, NOT a reflexivity result. That curve is Phase 6, and it needs (1)+(2) first.
